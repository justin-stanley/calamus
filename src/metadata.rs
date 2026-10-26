//! The OAuth client-identity document (`client-metadata.json`) and the
//! `client_id` derived from it.
//!
//! Two client shapes:
//!
//! * **localhost development** ([`ClientMetadata::localhost_dev`]) — atproto's
//!   special *localhost development client*. The `client_id` is
//!   `http://localhost` with `redirect_uri` and `scope` encoded as query
//!   parameters; no JWKS and no published metadata document are required, so a
//!   dev stack boots with zero PKI.
//!
//! * **confidential** ([`ClientMetadata::confidential`]) — a client with a real,
//!   edge-reachable metadata document, a JWKS (published at a `jwks_uri` or
//!   inline in the document), and `private_key_jwt` authentication using a key
//!   from [`crate::keys`].
//!
//! **`client_id` is not merely a config value — it IS the client's identity**,
//! and a PDS stores it against every existing grant. So this module takes the
//! URLs as given rather than deriving them: where the metadata document, the
//! callback and the JWKS live is the caller's decision, and a caller moving onto
//! this crate keeps its `client_id` byte for byte.
//!
//! Ported from FeatherReader `src/oauth/metadata.rs`, generalised: FeatherReader
//! derives the three URLs from its public origin under `/oauth/` and names
//! itself; here the caller supplies the URLs and the name, and the document
//! carries the same members with the same values for the same inputs.

use anyhow::{bail, Context as _, Result};
use serde_json::{json, Value};
use url::Url;

use crate::client_auth::AuthMethod;

/// Where a confidential client's public keys are published.
#[derive(Debug, Clone)]
pub enum Jwks {
    /// A URL the authorization server fetches the JWKS from (`jwks_uri`).
    Uri(Url),
    /// A JWKS document embedded in the metadata (`jwks`), for example
    /// [`SigningKey::jwks_document`](crate::keys::SigningKey::jwks_document).
    /// Public members only: a private key is refused at construction.
    Inline(Value),
}

/// Everything a client-metadata document is built from.
///
/// Fields are private and the only constructors validate, so a
/// `ClientMetadata` that exists has been checked. Leaving them public would make
/// the validation advisory, and the value it guards — `client_id` — is the
/// client's identity rather than a request parameter.
#[derive(Debug, Clone)]
pub struct ClientMetadata {
    client_id: String,
    redirect_uris: Vec<String>,
    scope: String,
    client_name: String,
    client_uri: Option<String>,
    /// `None` is the localhost dev client, which publishes no keys.
    jwks: Option<PublishedJwks>,
}

#[derive(Debug, Clone)]
enum PublishedJwks {
    Uri(String),
    Inline(Value),
}

/// JWK members that only a private (or symmetric) key carries.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Refuse userinfo and a fragment on a URL that is published in the document.
///
/// Userinfo would publish credentials inside the client's identity and in every
/// `redirect_uris` entry; a fragment is never part of a redirect URI (RFC 6749
/// §3.1.2) and changes nothing a server fetches.
fn refuse_credentials_and_fragment(what: &str, url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{what} must not carry credentials, got {url}");
    }
    if url.fragment().is_some() {
        bail!("{what} must not carry a fragment, got {url}");
    }
    Ok(())
}

/// A published URL that a PDS fetches or redirects to in production: https,
/// without credentials or a fragment.
fn require_https(what: &str, url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("{what} must be https, got {url}");
    }
    refuse_credentials_and_fragment(what, url)
}

/// A URL as published. A bare origin (`https://example.com/`) is published
/// without its trailing slash, as FeatherReader's `client_uri` always was; any
/// other URL is published exactly as `Url` serialises it.
fn published(url: &Url) -> String {
    if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        url[..url::Position::AfterPort].to_string()
    } else {
        url.to_string()
    }
}

/// Check an inline JWKS: an object whose `keys` is a non-empty array of JWK
/// objects, none carrying a private member. The document is public; a private
/// JWK here would hand the client's signing key to every PDS that fetches it.
fn validate_inline_jwks(jwks: &Value) -> Result<()> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .context("an inline JWKS must be an object with a `keys` array")?;
    if keys.is_empty() {
        bail!("an inline JWKS must carry at least one key");
    }
    for key in keys {
        let key = key
            .as_object()
            .context("every entry of an inline JWKS `keys` must be a JWK object")?;
        if let Some(member) = PRIVATE_JWK_MEMBERS.iter().find(|m| key.contains_key(**m)) {
            bail!(
                "an inline JWKS must carry public keys only, but a key has the private \
                 member {member:?}"
            );
        }
    }
    Ok(())
}

impl ClientMetadata {
    /// A confidential client authenticating with `private_key_jwt`.
    ///
    /// `client_id` is the URL the metadata document is served at; it, every
    /// redirect URI and a `jwks_uri` must be https without credentials or a
    /// fragment, and there must be at least one redirect URI. The redirect may
    /// be on a different origin from `client_id`. `client_uri`, when given, is
    /// the client's home page, also https.
    pub fn confidential(
        client_id: Url,
        redirect_uris: Vec<Url>,
        scope: &str,
        client_name: &str,
        client_uri: Option<Url>,
        jwks: Jwks,
    ) -> Result<Self> {
        require_https("client_id", &client_id)?;
        if redirect_uris.is_empty() {
            bail!("a client needs at least one redirect_uri");
        }
        for redirect in &redirect_uris {
            require_https("redirect_uri", redirect)?;
        }
        if let Some(client_uri) = &client_uri {
            require_https("client_uri", client_uri)?;
        }
        let jwks = match jwks {
            Jwks::Uri(uri) => {
                require_https("jwks_uri", &uri)?;
                PublishedJwks::Uri(uri.to_string())
            }
            Jwks::Inline(document) => {
                validate_inline_jwks(&document)?;
                PublishedJwks::Inline(document)
            }
        };
        Ok(Self {
            client_id: client_id.to_string(),
            redirect_uris: redirect_uris.iter().map(Url::to_string).collect(),
            scope: scope.to_string(),
            client_name: client_name.to_string(),
            client_uri: client_uri.as_ref().map(published),
            jwks: Some(jwks),
        })
    }

    /// atproto's localhost development client: a public client
    /// (`token_endpoint_auth_method: none`) whose `client_id` is the literal
    /// `http://localhost` with the redirect and scope in the query string.
    ///
    /// The redirect may be plain http (it is a loopback dev stack), and must not
    /// carry credentials or a fragment.
    ///
    /// Both query parameters are percent-encoded by the serializer rather than
    /// interpolated. `redirect_uri` contains `:` and `/`, and any `&` or `?` in a
    /// configured value would otherwise splice additional parameters into the
    /// client_id — a config value must never be able to redefine the redirect.
    pub fn localhost_dev(redirect_uri: Url, scope: &str, client_name: &str) -> Result<Self> {
        match redirect_uri.scheme() {
            "http" | "https" => {}
            other => bail!("redirect_uri must be http(s), got scheme {other:?}"),
        }
        refuse_credentials_and_fragment("redirect_uri", &redirect_uri)?;
        let redirect_uri = redirect_uri.to_string();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", scope)
            .finish();
        Ok(Self {
            client_id: format!("http://localhost?{query}"),
            redirect_uris: vec![redirect_uri],
            scope: scope.to_string(),
            client_name: client_name.to_string(),
            client_uri: None,
            jwks: None,
        })
    }

    /// The client's identity: the metadata document's URL for a confidential
    /// client, the `http://localhost?...` form for the dev client.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Where the browser is sent back to after the PDS authorizes (or denies):
    /// the first registered redirect URI.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uris[0]
    }

    /// The requested scope, as sent in PAR.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Where the published JWKS lives, for a confidential client with a
    /// `jwks_uri`. `None` for an inline JWKS and for the dev client.
    pub fn jwks_uri(&self) -> Option<&str> {
        match &self.jwks {
            Some(PublishedJwks::Uri(uri)) => Some(uri),
            _ => None,
        }
    }

    /// The client-authentication method this document publishes, and so the
    /// one every request must use.
    pub fn auth_method(&self) -> AuthMethod {
        if self.jwks.is_some() {
            AuthMethod::PrivateKeyJwt
        } else {
            AuthMethod::None
        }
    }

    /// The `client-metadata.json` document.
    pub fn document(&self) -> Value {
        let mut doc = json!({
            "client_id": self.client_id,
            "client_name": self.client_name,
            "redirect_uris": self.redirect_uris,
            "scope": self.scope,
            // `refresh_token` is required: without it the client cannot refresh and
            // every session dies at access-token expiry.
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "application_type": "web",
            "dpop_bound_access_tokens": true,
        });

        let obj = doc.as_object_mut().expect("built from a json! object");
        if let Some(client_uri) = &self.client_uri {
            obj.insert("client_uri".into(), json!(client_uri));
        }
        obj.insert(
            "token_endpoint_auth_method".into(),
            json!(self.auth_method().as_str()),
        );
        match &self.jwks {
            // The localhost dev client publishes no JWKS and authenticates with
            // nothing; advertising a jwks_uri we do not serve would make the PDS
            // fetch a 404.
            None => {}
            Some(jwks) => {
                obj.insert("token_endpoint_auth_signing_alg".into(), json!("ES256"));
                match jwks {
                    PublishedJwks::Uri(uri) => obj.insert("jwks_uri".into(), json!(uri)),
                    PublishedJwks::Inline(document) => obj.insert("jwks".into(), document.clone()),
                };
            }
        }
        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    const SCOPE: &str = "atproto transition:generic";

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn prod() -> ClientMetadata {
        ClientMetadata::confidential(
            url("https://feather-reader.com/oauth/client-metadata.json"),
            vec![url("https://feather-reader.com/oauth/callback")],
            SCOPE,
            "FeatherReader",
            Some(url("https://feather-reader.com")),
            Jwks::Uri(url("https://feather-reader.com/oauth/jwks.json")),
        )
        .unwrap()
    }

    fn dev() -> ClientMetadata {
        ClientMetadata::localhost_dev(
            url("http://127.0.0.1:8080/oauth/callback"),
            SCOPE,
            "FeatherReader (dev)",
        )
        .unwrap()
    }

    // ── configuration validation ─────────────────────────────────────────────

    /// Production `client_id` must be https — a PDS will not accept a plaintext
    /// client identity. Dev runs on loopback http, which is the documented
    /// exception.
    #[test]
    fn plain_http_is_rejected_in_production_but_allowed_in_dev() {
        assert!(ClientMetadata::confidential(
            url("http://feather-reader.com/oauth/client-metadata.json"),
            vec![url("http://feather-reader.com/oauth/callback")],
            "atproto",
            "FeatherReader",
            None,
            Jwks::Uri(url("https://feather-reader.com/oauth/jwks.json")),
        )
        .is_err());
        assert!(ClientMetadata::localhost_dev(
            url("http://127.0.0.1:8080/oauth/callback"),
            "atproto",
            "FeatherReader (dev)"
        )
        .is_ok());
    }

    /// Userinfo would publish credentials inside the client's identity and in
    /// every `redirect_uris` entry; a fragment is never part of a redirect URI
    /// (RFC 6749 §3.1.2) and has no meaning in a `client_id`.
    #[test]
    fn a_client_id_or_redirect_carrying_credentials_or_a_fragment_is_refused() {
        let jwks = || Jwks::Uri(url("https://x.example/jwks.json"));
        for (client_id, redirect) in [
            ("https://u:p@x.example/m.json", "https://x.example/cb"),
            ("https://u@x.example/m.json", "https://x.example/cb"),
            ("https://x.example/m.json#frag", "https://x.example/cb"),
            ("https://x.example/m.json", "https://u:p@x.example/cb"),
            ("https://x.example/m.json", "https://x.example/cb#frag"),
            ("https://x.example/m.json", "http://x.example/cb"),
        ] {
            assert!(
                ClientMetadata::confidential(
                    url(client_id),
                    vec![url(redirect)],
                    "atproto",
                    "x",
                    None,
                    jwks()
                )
                .is_err(),
                "accepted client_id {client_id} with redirect {redirect}"
            );
        }
        for jwks_uri in [
            "http://x.example/jwks.json",
            "https://u:p@x.example/jwks.json",
        ] {
            assert!(
                ClientMetadata::confidential(
                    url("https://x.example/m.json"),
                    vec![url("https://x.example/cb")],
                    "atproto",
                    "x",
                    None,
                    Jwks::Uri(url(jwks_uri)),
                )
                .is_err(),
                "accepted jwks_uri {jwks_uri}"
            );
        }
        for redirect in ["http://u:p@127.0.0.1:8080/cb", "http://127.0.0.1:8080/cb#f"] {
            assert!(
                ClientMetadata::localhost_dev(url(redirect), "atproto", "x").is_err(),
                "accepted dev redirect {redirect}"
            );
        }
    }

    /// A client with nowhere to send the browser back to cannot complete a
    /// login, and [`ClientMetadata::redirect_uri`] would have nothing to return.
    #[test]
    fn a_confidential_client_needs_at_least_one_redirect_uri() {
        assert!(ClientMetadata::confidential(
            url("https://x.example/m.json"),
            vec![],
            "atproto",
            "x",
            None,
            Jwks::Uri(url("https://x.example/jwks.json")),
        )
        .is_err());
    }

    // ── production document ──────────────────────────────────────────────────

    #[test]
    fn the_production_document_is_a_dpop_bound_confidential_client() {
        let doc = prod().document();
        assert_eq!(doc["client_id"], prod().client_id());
        assert_eq!(doc["redirect_uris"][0], prod().redirect_uri());
        assert_eq!(doc["jwks_uri"], prod().jwks_uri().unwrap());
        assert_eq!(doc["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(doc["token_endpoint_auth_signing_alg"], "ES256");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
        assert_eq!(doc["application_type"], "web");
        assert_eq!(doc["response_types"][0], "code");
        let grants: Vec<&str> = doc["grant_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.as_str().unwrap())
            .collect();
        assert!(grants.contains(&"authorization_code"));
        assert!(
            grants.contains(&"refresh_token"),
            "without refresh_token the client cannot refresh and sessions die at token expiry"
        );
    }

    /// **`client_id` is the client's identity, and the document is what a PDS
    /// fetches and caches for it.** FeatherReader publishes this document today;
    /// built from the same inputs, `ClientMetadata` must serialise it to the
    /// same bytes, so moving FeatherReader onto calamus changes nothing a PDS
    /// can see.
    ///
    /// The literal is FeatherReader's `client_metadata()` for
    /// `ClientConfig::new("https://example.com", "atproto transition:generic",
    /// false)`, derived from its code at `d809794`: the `json!` object (a
    /// `BTreeMap`, as nothing in either dependency tree enables serde_json's
    /// `preserve_order`, so members are sorted), `client_uri` the bare origin
    /// with no trailing slash, and the three `/oauth/...` URLs.
    #[test]
    fn the_confidential_document_is_byte_identical_to_featherreaders() {
        let metadata = ClientMetadata::confidential(
            url("https://example.com/oauth/client-metadata.json"),
            vec![url("https://example.com/oauth/callback")],
            "atproto transition:generic",
            "FeatherReader",
            Some(url("https://example.com")),
            Jwks::Uri(url("https://example.com/oauth/jwks.json")),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&metadata.document()).unwrap(),
            concat!(
                r#"{"application_type":"web","#,
                r#""client_id":"https://example.com/oauth/client-metadata.json","#,
                r#""client_name":"FeatherReader","#,
                r#""client_uri":"https://example.com","#,
                r#""dpop_bound_access_tokens":true,"#,
                r#""grant_types":["authorization_code","refresh_token"],"#,
                r#""jwks_uri":"https://example.com/oauth/jwks.json","#,
                r#""redirect_uris":["https://example.com/oauth/callback"],"#,
                r#""response_types":["code"],"#,
                r#""scope":"atproto transition:generic","#,
                r#""token_endpoint_auth_method":"private_key_jwt","#,
                r#""token_endpoint_auth_signing_alg":"ES256"}"#,
            )
        );
    }

    /// The same, for FeatherReader's localhost dev client
    /// (`ClientConfig::new("http://127.0.0.1:8080", "atproto
    /// transition:generic", true)`): in dev the `client_id` itself encodes the
    /// redirect and scope, so it is identity too.
    #[test]
    fn the_dev_document_is_byte_identical_to_featherreaders() {
        assert_eq!(
            serde_json::to_string(&dev().document()).unwrap(),
            concat!(
                r#"{"application_type":"web","#,
                r#""client_id":"http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Foauth%2Fcallback&scope=atproto+transition%3Ageneric","#,
                r#""client_name":"FeatherReader (dev)","#,
                r#""dpop_bound_access_tokens":true,"#,
                r#""grant_types":["authorization_code","refresh_token"],"#,
                r#""redirect_uris":["http://127.0.0.1:8080/oauth/callback"],"#,
                r#""response_types":["code"],"#,
                r#""scope":"atproto transition:generic","#,
                r#""token_endpoint_auth_method":"none"}"#,
            )
        );
    }

    // ── inline JWKS ──────────────────────────────────────────────────────────

    /// A client with no `jwks_uri` to serve publishes its key inside the
    /// document as `jwks`. Exactly one of the two may appear: a document with
    /// both leaves the authorization server to choose.
    #[test]
    fn an_inline_jwks_is_published_as_jwks_not_jwks_uri() {
        let key = SigningKey::generate("rubrica-1");
        let jwks = key.jwks_document().unwrap();
        let metadata = ClientMetadata::confidential(
            url("https://rubrica.example/client-metadata.json"),
            vec![url("https://rubrica.example/callback")],
            "atproto",
            "Rubrica",
            None,
            Jwks::Inline(jwks.clone()),
        )
        .unwrap();
        let doc = metadata.document();
        assert_eq!(doc["jwks"], jwks);
        assert!(doc.get("jwks_uri").is_none());
        assert_eq!(metadata.jwks_uri(), None);
        assert_eq!(doc["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(doc["token_endpoint_auth_signing_alg"], "ES256");
        // No client_uri was given, so none is published.
        assert!(doc.get("client_uri").is_none());
    }

    /// **The document is public.** An inline JWKS built from the private JWK
    /// rather than `jwks_document()` would publish the client's signing key to
    /// every PDS that fetches it, so private members are refused outright; so
    /// is anything that is not a JWKS at all.
    #[test]
    fn an_inline_jwks_carrying_a_private_key_or_no_keys_is_refused() {
        let key = SigningKey::generate("k");
        let private: Value = serde_json::from_str(&key.to_jwk_json().unwrap()).unwrap();
        for jwks in [
            json!({ "keys": [private] }),
            json!({ "keys": [] }),
            json!({ "keys": "nope" }),
            json!({ "keys": ["nope"] }),
            json!({}),
            json!([]),
            json!({ "keys": [{"kty": "oct", "k": "c2VjcmV0"}] }),
        ] {
            assert!(
                ClientMetadata::confidential(
                    url("https://x.example/m.json"),
                    vec![url("https://x.example/cb")],
                    "atproto",
                    "x",
                    None,
                    Jwks::Inline(jwks.clone()),
                )
                .is_err(),
                "accepted inline jwks {jwks}"
            );
        }
    }

    /// Rubrica's shape: it only wants to know who signed in, so its scope is
    /// exactly `atproto`, and its redirect lives on a different origin from its
    /// metadata document. Neither is FeatherReader's shape, and neither may be
    /// refused or rewritten.
    #[test]
    fn the_identity_only_shape_is_accepted() {
        let key = SigningKey::generate("rubrica-1");
        let metadata = ClientMetadata::confidential(
            url("https://meta.rubrica.example/client-metadata.json"),
            vec![url("https://app.rubrica.example/auth/done")],
            "atproto",
            "Rubrica",
            Some(url("https://rubrica.example")),
            Jwks::Inline(key.jwks_document().unwrap()),
        )
        .unwrap();
        assert_eq!(metadata.scope(), "atproto");
        assert_eq!(
            metadata.client_id(),
            "https://meta.rubrica.example/client-metadata.json"
        );
        assert_eq!(
            metadata.redirect_uri(),
            "https://app.rubrica.example/auth/done"
        );
        let doc = metadata.document();
        assert_eq!(doc["scope"], "atproto");
        assert_eq!(
            doc["redirect_uris"],
            json!(["https://app.rubrica.example/auth/done"])
        );
        assert_eq!(doc["client_name"], "Rubrica");
        assert_eq!(doc["client_uri"], "https://rubrica.example");
    }

    /// The method a flow negotiates must be the one the document publishes, or
    /// the authorization server is told one thing and sent another.
    #[test]
    fn the_auth_method_agrees_with_the_published_document() {
        for metadata in [prod(), dev()] {
            assert_eq!(
                metadata.document()["token_endpoint_auth_method"],
                metadata.auth_method().as_str()
            );
        }
        assert_eq!(prod().auth_method(), AuthMethod::negotiate(false));
        assert_eq!(dev().auth_method(), AuthMethod::negotiate(true));
    }

    // ── dev document ─────────────────────────────────────────────────────────

    /// The localhost dev client needs NO published metadata and NO JWKS — that
    /// is the whole point of it. Advertising a `jwks_uri` we do not serve would
    /// make the PDS fetch a 404.
    #[test]
    fn the_dev_document_declares_no_jwks_and_no_client_authentication() {
        let doc = dev().document();
        assert!(doc.get("jwks_uri").is_none());
        assert_eq!(doc["token_endpoint_auth_method"], "none");
        assert_eq!(doc["dpop_bound_access_tokens"], true);
    }

    /// The dev `client_id` carries redirect_uri and scope in its QUERY STRING,
    /// so both must be percent-encoded. Interpolating them raw would splice the
    /// `:` and `/` of the redirect and, worse, let any `&` or `?` in a
    /// configured value inject further parameters.
    #[test]
    fn the_dev_client_id_percent_encodes_its_query_parameters() {
        let id = dev().client_id().to_string();
        assert!(id.starts_with("http://localhost?"), "got {id}");
        assert!(
            id.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Foauth%2Fcallback"),
            "redirect_uri was not percent-encoded: {id}"
        );
        // The space in "atproto transition:generic" must be encoded too.
        assert!(
            id.contains("scope=atproto+transition%3Ageneric")
                || id.contains("scope=atproto%20transition%3Ageneric"),
            "scope was not percent-encoded: {id}"
        );
        assert!(
            !id.contains(' '),
            "a raw space would make an invalid URL: {id}"
        );
    }

    /// A hostile or fat-fingered config value must not be able to add
    /// parameters to the dev client_id.
    #[test]
    fn a_query_delimiter_in_the_scope_cannot_inject_extra_parameters() {
        let cfg = ClientMetadata::localhost_dev(
            url("http://127.0.0.1:8080/oauth/callback"),
            "atproto&redirect_uri=https://evil.example",
            "FeatherReader (dev)",
        )
        .unwrap();
        let id = cfg.client_id();
        assert_eq!(
            id.matches("redirect_uri=").count(),
            1,
            "scope injected a second redirect_uri: {id}"
        );
        assert!(id.contains("%26"), "the `&` was not encoded: {id}");
    }

    #[test]
    fn the_dev_document_and_client_id_agree_on_the_redirect_uri() {
        let doc = dev().document();
        assert_eq!(doc["redirect_uris"][0], dev().redirect_uri());
        assert_eq!(doc["client_id"], dev().client_id());
    }
}
