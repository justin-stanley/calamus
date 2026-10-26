//! The ES256 signing key, and the public documents derived from it.
//!
//! An atproto OAuth confidential client authenticates to the authorization server with
//! `private_key_jwt`, signing a client assertion with a long-lived ES256 key whose public
//! half is published (as `jwks` inline in the client metadata, or at a `jwks_uri`). The same
//! type also holds the per-session DPoP keys.
//!
//! The thumbprint is RFC 7638, computed over the PUBLIC members only (`crv`, `kty`, `x`,
//! `y`) in lexicographic order: never over the raw JWK text, and never including `d`.
//!
//! The JWK *format* this writes is the one FeatherReader (and before it, its Node sidecar)
//! persists, so keys move between them unchanged. Persisting a key at rest arrives with the
//! `AtRestCodec` trait in a later stage; this module is the pure half.
//!
//! Ported from FeatherReader `src/oauth/keys.rs`.

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::SecretKey;
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};

/// The JOSE algorithm this client signs assertions with. atproto's OAuth profile
/// requires ES256 for `private_key_jwt`.
const ALG: &str = "ES256";

/// Extract a required string member from a JWK object.
fn member<'a>(jwk: &'a Value, name: &str) -> Result<&'a str> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWK is missing the required `{name}` member"))
}

/// RFC 7638 thumbprint of an EC JWK.
///
/// The construction is the whole point: take ONLY the required members for the
/// key type (`crv`, `kty`, `x`, `y` for EC), emit them as compact JSON in
/// lexicographic order, SHA-256 that, base64url-encode without padding.
///
/// Hashing the raw JWK text instead would make the value depend on whitespace,
/// member order and any extra members, and would fold in the private `d` — it
/// would never match what the PDS computes.
fn thumbprint_of_members(jwk: &Value) -> Result<String> {
    let (crv, kty, x, y) = (
        member(jwk, "crv")?,
        member(jwk, "kty")?,
        member(jwk, "x")?,
        member(jwk, "y")?,
    );
    if kty != "EC" {
        bail!("unsupported JWK key type {kty:?}; expected EC");
    }
    if crv != "P-256" {
        bail!("unsupported JWK curve {crv:?}; only P-256 is supported");
    }
    // `x`/`y` are unpadded base64url in a well-formed EC JWK. The check is on
    // the ALPHABET, which is all that is needed for the property that matters
    // here: no member can require JSON escaping, so the canonical form is
    // unambiguous. It is not a validity check — length and decodability are not
    // verified, and do not need to be, since the caller either supplies our own
    // key or is about to hand the JWK to `p256` anyway.
    for (name, value) in [("x", x), ("y", y)] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("JWK member `{name}` is not unpadded base64url");
        }
    }
    // Serialized, not interpolated, so the escaping is the serializer's job.
    // The literal below is also WRITTEN in lexicographic order, so the output is
    // RFC-canonical whether `serde_json::Map` is a `BTreeMap` (the default) or
    // an insertion-ordered map (were `preserve_order` ever pulled in by feature
    // unification elsewhere in the graph).
    let canonical = serde_json::to_string(&json!({"crv": crv, "kty": kty, "x": x, "y": y}))
        .context("serializing the canonical JWK")?;
    Ok(URL_SAFE_NO_PAD.encode(digest(&SHA256, canonical.as_bytes()).as_ref()))
}

/// Decode one base64url JWK member that must be exactly 32 bytes (a P-256 coordinate or
/// scalar).
fn fixed32(jwk: &Value, name: &str) -> Result<[u8; 32]> {
    let raw = URL_SAFE_NO_PAD
        .decode(member(jwk, name)?)
        .map_err(|err| anyhow!("JWK member `{name}` is not base64url: {err}"))?;
    raw.try_into()
        .map_err(|raw: Vec<u8>| anyhow!("JWK member `{name}` is {} bytes, not 32", raw.len()))
}

/// The public members (`kty`, `crv`, `x`, `y`) of a P-256 public key.
///
/// p256 0.14 removed JWK support (it left `elliptic-curve`), so the JWK is built here:
/// `x` and `y` are the 32-byte big-endian affine coordinates, base64url without
/// padding (RFC 7518 §6.2.1).
fn public_members(public: &p256::PublicKey) -> Result<serde_json::Map<String, Value>> {
    let point = public.to_sec1_point(false);
    let (x, y) = (
        point
            .x()
            .ok_or_else(|| anyhow!("public key is the identity"))?,
        point
            .y()
            .ok_or_else(|| anyhow!("public key has no y coordinate"))?,
    );
    let mut m = serde_json::Map::new();
    m.insert("kty".into(), json!("EC"));
    m.insert("crv".into(), json!("P-256"));
    m.insert("x".into(), json!(URL_SAFE_NO_PAD.encode(x)));
    m.insert("y".into(), json!(URL_SAFE_NO_PAD.encode(y)));
    Ok(m)
}

/// The confidential client's long-lived ES256 signing key.
pub struct SigningKey {
    secret: SecretKey,
    kid: String,
}

impl SigningKey {
    /// Generate a fresh P-256 key.
    ///
    /// Draws from the OS CSPRNG via `getrandom`, the same source as the rest of
    /// the app, rather than pulling in a second RNG stack. A uniformly random
    /// 32-byte value is a valid P-256 scalar with overwhelming probability; the
    /// retry covers the ~2^-32 case where it lands outside the curve order.
    pub fn generate(kid: &str) -> Self {
        for _ in 0..8 {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes)
                .expect("OS CSPRNG unavailable; refusing to generate a signing key");
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Self {
                    secret,
                    kid: kid.to_string(),
                };
            }
        }
        unreachable!("8 consecutive invalid P-256 scalars is not physically plausible")
    }

    /// Parse a JWK, tolerating the extra members (`kid`, `alg`, `key_ops`,
    /// `use`) that both this module and the sidecar attach.
    pub fn from_jwk_json(jwk_json: &str, kid: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(jwk_json).context("key file is not valid JSON")?;
        if v.get("d").is_none() {
            bail!("JWK has no `d` member; a signing key must be a private key");
        }
        // Only the members RFC 7518 defines for an EC private key are read, so an
        // unexpected extra member can never make a valid key fail to parse.
        let secret = (|| -> Result<SecretKey> {
            if member(&v, "kty")? != "EC" || member(&v, "crv")? != "P-256" {
                bail!("not an EC P-256 key");
            }
            let d = fixed32(&v, "d")?;
            let secret =
                SecretKey::from_slice(&d).map_err(|_| anyhow!("`d` is not a valid scalar"))?;
            // The public members must be the public key of `d` (p256 0.13's JWK parser
            // checked this; we must too): otherwise a file could pair our private scalar
            // with someone else's public key, and the thumbprint would name a key we
            // don't hold.
            let point = secret.public_key().to_sec1_point(false);
            let (x, y) = (fixed32(&v, "x")?, fixed32(&v, "y")?);
            if point.x().map(|c| c.as_slice()) != Some(&x[..])
                || point.y().map(|c| c.as_slice()) != Some(&y[..])
            {
                bail!("the public members do not match `d`");
            }
            Ok(secret)
        })()
        .map_err(|err| anyhow!("not a valid P-256 private JWK: {err:#}"))?;
        // Prefer the kid already in the file: it is what a PDS may have cached
        // against the published JWKS.
        let kid = v
            .get("kid")
            .and_then(Value::as_str)
            .unwrap_or(kid)
            .to_string();
        Ok(Self { secret, kid })
    }

    /// The PRIVATE JWK, for persistence. Carries `kid`/`alg`/`key_ops` so a
    /// rollback to the sidecar finds the key under the same identifier.
    pub fn to_jwk_json(&self) -> Result<String> {
        let mut obj = public_members(&self.secret.public_key())?;
        obj.insert(
            "d".into(),
            json!(URL_SAFE_NO_PAD.encode(self.secret.to_bytes())),
        );
        obj.insert("kid".into(), json!(self.kid));
        obj.insert("alg".into(), json!(ALG));
        // `key_ops`, not `use`, on the PRIVATE JWK: `jose` warns that a private
        // JWK carrying `use` will be rejected in a future release, which would
        // break the rollback path this shared format exists to preserve.
        //
        // (The sidecar writes NEITHER — `JoseKey.generate(...).privateJwk` is
        // just `{kty, kid, crv, x, y, d}`. An earlier version of this comment
        // claimed `key_ops` matched the sidecar; it does not. The change stands
        // on the deprecation alone, and jwk-jose loads the result warning-free.)
        obj.insert("key_ops".into(), json!(["sign"]));
        serde_json::to_string(&Value::Object(obj)).context("rendering the private JWK")
    }

    /// The PUBLIC JWK — what `/jwks.json` serves. Never contains `d`.
    pub fn public_jwk(&self) -> Result<Value> {
        // Built from the public key alone, so the private scalar cannot be in it.
        let mut obj = public_members(&self.secret.public_key())?;
        obj.insert("kid".into(), json!(self.kid));
        obj.insert("alg".into(), json!(ALG));
        obj.insert("use".into(), json!("sig"));
        Ok(Value::Object(obj))
    }

    /// The document served at `jwks_uri`, so the PDS can verify our assertions.
    pub fn jwks_document(&self) -> Result<Value> {
        Ok(json!({ "keys": [self.public_jwk()?] }))
    }

    /// RFC 7638 thumbprint of this key's public half.
    pub fn thumbprint(&self) -> Result<String> {
        thumbprint_of_members(&self.public_jwk()?)
    }

    /// RFC 7638 thumbprint of an arbitrary EC JWK document.
    pub fn public_thumbprint_of(jwk_json: &str) -> Result<String> {
        let v: Value = serde_json::from_str(jwk_json).context("not valid JSON")?;
        thumbprint_of_members(&v)
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The raw secret, for [`super::jwt`] to sign with. Deliberately
    /// `pub(crate)`: nothing outside this crate should be able to reach the
    /// private scalar, and nothing outside [`super::jwt`] needs to.
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "featherreader-oauth-1";

    /// A P-256 keypair and its RFC 7638 thumbprint, generated by `jose` 5.10 —
    /// an INDEPENDENT implementation, not this one. Regenerate with:
    /// ```text
    /// node --input-type=module -e 'import {generateKeyPair,exportJWK,calculateJwkThumbprint} from "jose";
    ///   const {publicKey,privateKey}=await generateKeyPair("ES256",{extractable:true});
    ///   console.log(JSON.stringify({pub:await exportJWK(publicKey),
    ///     priv:await exportJWK(privateKey),
    ///     tp:await calculateJwkThumbprint(await exportJWK(publicKey),"sha256")}))'
    /// ```
    const JOSE_PRIVATE_JWK: &str = r#"{
        "kty": "EC",
        "x": "HWngJQsJ6v606UgaeEf0Xv_Fe3c4MwChe3ouzCDZf3I",
        "y": "wwvoKJJUKd57bdQ3f3GpVuW-0-1MI_FhMt86Q9M95Ig",
        "crv": "P-256",
        "d": "ltBp9dkK7xkLm9VXOd6CMiLdFRKWQwVrN0Vf8QwC3a4"
    }"#;
    const JOSE_THUMBPRINT: &str = "nfjQX8hSYRpE05ADhZk6PVsPatJ6MqzqvzYxlL-kMC8";

    // ── thumbprint ───────────────────────────────────────────────────────────

    /// **The property the earlier WIP got wrong.** It hashed the raw JWK *string*,
    /// which depends on whitespace, member order and any extra members, and would
    /// happily include the private `d`. RFC 7638 hashes canonical JSON of exactly
    /// {crv, kty, x, y}. A value that does not match this is rejected by every PDS.
    #[test]
    fn thumbprint_matches_an_independent_rfc7638_implementation() {
        let key = SigningKey::from_jwk_json(JOSE_PRIVATE_JWK, KID).unwrap();
        assert_eq!(key.thumbprint().unwrap(), JOSE_THUMBPRINT);
    }

    /// The thumbprint identifies the PUBLIC key, so the private JWK and the
    /// public JWK of the same keypair must produce the same value.
    #[test]
    fn thumbprint_is_identical_for_the_private_and_public_halves() {
        let key = SigningKey::from_jwk_json(JOSE_PRIVATE_JWK, KID).unwrap();
        let public_only = serde_json::to_string(&key.public_jwk().unwrap()).unwrap();
        let reloaded = SigningKey::public_thumbprint_of(&public_only).unwrap();
        assert_eq!(reloaded, key.thumbprint().unwrap());
        assert_eq!(reloaded, JOSE_THUMBPRINT);
    }

    /// Canonicalization means member order and whitespace in the INPUT cannot
    /// change the output — the failure mode of hashing the raw string.
    #[test]
    fn thumbprint_ignores_member_order_and_whitespace() {
        let reordered = r#"{"y":"wwvoKJJUKd57bdQ3f3GpVuW-0-1MI_FhMt86Q9M95Ig","d":"ltBp9dkK7xkLm9VXOd6CMiLdFRKWQwVrN0Vf8QwC3a4","crv":"P-256","kty":"EC","x":"HWngJQsJ6v606UgaeEf0Xv_Fe3c4MwChe3ouzCDZf3I"}"#;
        let key = SigningKey::from_jwk_json(reordered, KID).unwrap();
        assert_eq!(key.thumbprint().unwrap(), JOSE_THUMBPRINT);
    }

    // ── generation and round-trip ────────────────────────────────────────────

    /// The canonical form must be real JSON with real escaping. Building it by
    /// string interpolation produced invalid JSON — and therefore a thumbprint
    /// no other implementation reproduces — for any member containing a quote,
    /// a backslash or a control character.
    ///
    /// Such members cannot occur in a well-formed EC JWK (`x`/`y` are base64url),
    /// so the fix is to reject them rather than hash them. That matters because
    /// this function takes JWKs from REMOTE parties.
    #[test]
    fn public_thumbprint_of_rejects_members_that_are_not_base64url() {
        for x in [r#"A\"A"#, r#"A\\A"#, "A A", "A+A", "A/A", "AAA=", "", "é"] {
            let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":x,"y":"BBB"});
            assert!(
                SigningKey::public_thumbprint_of(&jwk.to_string()).is_err(),
                "accepted a non-base64url x: {x:?}"
            );
        }
    }

    #[test]
    fn public_thumbprint_of_rejects_malformed_or_non_ec_jwks() {
        for jwk in [
            r#"{"kty":"RSA","crv":"P-256","x":"AAA","y":"BBB"}"#,
            r#"{"kty":"EC","crv":"P-521","x":"AAA","y":"BBB"}"#,
            r#"{"kty":"EC","crv":"P-256","x":"AAA"}"#,
            r#"{"kty":"EC","crv":"P-256"}"#,
            r#"{"kty":"EC","crv":"P-256","x":123,"y":"BBB"}"#,
            "not json",
            "[]",
        ] {
            assert!(
                SigningKey::public_thumbprint_of(jwk).is_err(),
                "accepted {jwk}"
            );
        }
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SigningKey::generate(KID);
        let b = SigningKey::generate(KID);
        assert_ne!(a.thumbprint().unwrap(), b.thumbprint().unwrap());
    }

    #[test]
    fn a_generated_key_round_trips_through_its_jwk() {
        let key = SigningKey::generate(KID);
        let json = key.to_jwk_json().unwrap();
        let back = SigningKey::from_jwk_json(&json, KID).unwrap();
        assert_eq!(back.thumbprint().unwrap(), key.thumbprint().unwrap());
    }

    /// The persisted JWK is the PRIVATE one (it has to be — it is the signing
    /// key), and it carries the kid so a rollback to the sidecar finds it.
    #[test]
    fn the_persisted_jwk_carries_the_private_scalar_and_the_kid() {
        let key = SigningKey::generate(KID);
        let v: serde_json::Value = serde_json::from_str(&key.to_jwk_json().unwrap()).unwrap();
        assert!(
            v.get("d").is_some(),
            "the signing key must persist its scalar"
        );
        assert_eq!(v["kid"], KID);
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "P-256");
    }

    // ── what gets published ──────────────────────────────────────────────────

    /// The single most important leak to not have: `d` must never reach the
    /// JWKS endpoint.
    #[test]
    fn the_public_jwk_and_jwks_never_contain_the_private_scalar() {
        let key = SigningKey::generate(KID);
        let public = key.public_jwk().unwrap();
        assert!(public.get("d").is_none());

        let jwks = key.jwks_document().unwrap();
        let rendered = serde_json::to_string(&jwks).unwrap();
        assert!(
            !rendered.contains("\"d\""),
            "JWKS leaked the private scalar: {rendered}"
        );
        // **The scalar of the key UNDER TEST, not a literal.**
        //
        // This line used to hard-code the `d` of the fixture JWK above. The key
        // here is `SigningKey::generate`, freshly random every run, so that
        // literal could never appear whatever the code did — the assertion was
        // unconditionally true.
        //
        // It also covers what the `"d"` check above cannot: material leaking
        // under some OTHER member name. A scalar copied into `x` passes a search
        // for `"d"` and fails this.
        let private: serde_json::Value = serde_json::from_str(&key.to_jwk_json().unwrap()).unwrap();
        let scalar = private["d"].as_str().expect("the private JWK has a scalar");
        assert!(
            !rendered.contains(scalar),
            "JWKS leaked the private scalar: {rendered}"
        );
    }

    #[test]
    fn the_jwks_document_is_a_keys_array_with_the_verification_metadata() {
        let key = SigningKey::from_jwk_json(JOSE_PRIVATE_JWK, KID).unwrap();
        let jwks = key.jwks_document().unwrap();
        let entry = &jwks["keys"][0];
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        assert_eq!(entry["kty"], "EC");
        assert_eq!(entry["crv"], "P-256");
        assert_eq!(entry["kid"], KID);
        assert_eq!(entry["alg"], "ES256");
        assert_eq!(entry["use"], "sig");
        assert_eq!(entry["x"], "HWngJQsJ6v606UgaeEf0Xv_Fe3c4MwChe3ouzCDZf3I");
    }

    // ── persistence ──────────────────────────────────────────────────────────

    /// p256 0.14 dropped JWK support, so this module parses JWKs itself. The check the
    /// library used to make is now ours: the public members must be the public key of
    /// `d`. Otherwise a file could pair a private scalar with someone else's public
    /// key, and the thumbprint (which hashes x/y) would identify a key we don't hold.
    #[test]
    fn a_jwk_whose_public_members_do_not_match_d_is_refused() {
        let other = SigningKey::generate(KID).public_jwk().unwrap();
        let mut v: serde_json::Value = serde_json::from_str(JOSE_PRIVATE_JWK).unwrap();
        v["x"] = other["x"].clone();
        v["y"] = other["y"].clone();
        let err = SigningKey::from_jwk_json(&v.to_string(), KID)
            .err()
            .expect("mismatched JWK accepted");
        // p256 0.13 refused this too ("crypto error"); the prefix is unchanged.
        assert!(
            format!("{err:#}").contains("not a valid P-256 private JWK"),
            "{err:#}"
        );
    }

    #[test]
    fn a_jwk_with_a_short_coordinate_or_scalar_is_refused() {
        for member in ["x", "y", "d"] {
            let mut v: serde_json::Value = serde_json::from_str(JOSE_PRIVATE_JWK).unwrap();
            v[member] = serde_json::json!("AAAA");
            assert!(
                SigningKey::from_jwk_json(&v.to_string(), KID).is_err(),
                "short `{member}` accepted"
            );
        }
    }

    #[test]
    fn the_private_jwk_uses_key_ops_rather_than_use() {
        let key = SigningKey::generate(KID);
        let v: serde_json::Value = serde_json::from_str(&key.to_jwk_json().unwrap()).unwrap();
        assert_eq!(v["key_ops"], serde_json::json!(["sign"]));
        assert!(
            v.get("use").is_none(),
            "private JWK carries `use`, which jose deprecates"
        );
        // The PUBLIC half is a JWKS entry, where `use: sig` is the norm.
        assert_eq!(key.public_jwk().unwrap()["use"], "sig");
    }
}
