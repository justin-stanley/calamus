//! Fetching the JSON documents OAuth discovery depends on.
//!
//! Three rules apply to every document here, and each exists because the
//! reference client enforces it:
//!
//! * **No redirects.** The mix-up defence compares a document's `issuer` against
//!   the URL it was fetched from; a `302` would make that comparison meaningless
//!   while still appearing to pass. See [`Fetcher::get_no_redirect`].
//! * **Status exactly 200.** Not "2xx", not "whatever parsed". A `204` or a `206`
//!   is not a metadata document.
//! * **Content type must be JSON.** A server answering `text/html` is not
//!   serving the document we asked for, whatever the bytes happen to parse as.
//!
//! On top of the SSRF guard and the body cap those bring with them, and a bound
//! on the JSON structure a body may carry before it is parsed
//! ([`refuse_a_structure_explosion`]).
//!
//! Ported from FeatherReader `src/oauth/fetch.rs`; the structure guard
//! ([`count_structural_chars`], [`refuse_a_structure_explosion`],
//! [`StructureExplosion`], [`MAX_LIST_STRUCTURAL_CHARS`]) from its
//! `src/atproto.rs`, which shares it with its `listRecords` parser.

use anyhow::{bail, Context as _, Result};
use serde_json::Value;

use crate::net::Fetcher;

/// Content types accepted for OAuth metadata documents.
pub const JSON: &[&str] = &["application/json"];

/// Content types accepted for DID documents. `did+ld+json` is what
/// `plc.directory` actually serves.
pub const DID_JSON: &[&str] = &[
    "application/json",
    "application/did+ld+json",
    "application/did+json",
];

/// Validate a response's status and content type before its body is trusted.
///
/// Split out from the fetch so it is testable without a network: this is the
/// part with the rules in it.
fn check_meta(status: u16, content_type: Option<&str>, allowed: &[&str]) -> Result<()> {
    if status != 200 {
        bail!("expected status 200, got {status}");
    }
    let Some(raw) = content_type else {
        bail!("response has no Content-Type; refusing to parse it as JSON");
    };
    // `application/json; charset=utf-8` — compare only the media type, and
    // case-insensitively (RFC 9110 §8.3.1 makes it case-insensitive).
    let media = raw
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !allowed.iter().any(|a| *a == media) {
        bail!("unexpected Content-Type {media:?}; expected one of {allowed:?}");
    }
    Ok(())
}

/// Fetch a JSON document, requiring 200 and an acceptable content type.
pub async fn get_json(fetcher: &Fetcher, url: &str, allowed: &[&str]) -> Result<Value> {
    get_json_optional(fetcher, url, allowed)
        .await?
        .with_context(|| format!("document not found at {url}"))
}

/// As [`get_json`], but a `404` means **absent** rather than failed.
///
/// `/.well-known/oauth-protected-resource` legitimately does not exist on some
/// hosts, and "absent" is a different answer from "the fetch went wrong".
pub async fn get_json_optional(
    fetcher: &Fetcher,
    url: &str,
    allowed: &[&str],
) -> Result<Option<Value>> {
    let resp = fetcher
        .get_no_redirect(url, &[])
        .await
        .with_context(|| format!("fetching {url}"))?;

    let status = resp.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    check_meta(status, content_type.as_deref(), allowed)
        .with_context(|| format!("fetching {url}"))?;

    let body = fetcher
        .read_capped(resp)
        .await
        .with_context(|| format!("reading {url}"))?;
    // **The host here is chosen by whoever typed the handle, and this runs before
    // anyone is authenticated.** `resolve::did_document` fetches a `did:web`
    // document from the host named in the DID, and `discovery::discover` fetches
    // `/.well-known/oauth-authorization-server` from the PDS URL that came with
    // it. `read_capped` bounds the wire at 8 MB, which is the INPUT to the
    // amplification, not a limit on it — 8 MB of `{"":0}` objects measured 789 MB
    // of `Value`.
    //
    // The node bound rather than a length bound, because unlike an error peek
    // these bodies are legitimately structural: a DID document carries services
    // and verification methods, and authorization-server metadata is a few dozen
    // arrays. Bounding structure permits any amount of text.
    refuse_a_structure_explosion(&body, &format!("the body of {url}"))?;
    let value =
        serde_json::from_slice(&body).with_context(|| format!("{url} is not valid JSON"))?;
    Ok(Some(value))
}

/// The most nodes a body may ask us to build: a count of
/// [`count_structural_chars`], checked before the body is parsed.
///
/// **A bound on the parse, checked before the parse.** Every other limit is
/// consulted after `serde_json` has already materialised the document, which
/// cannot prevent the allocation it exists to prevent: one 8 MB response of
/// `{"":0}` objects was measured retaining 824 MB, a 98x wire-to-heap
/// amplification, on a 512 MB box. A byte budget does not see it until the
/// memory is already spent.
///
/// **640 000, measured** (in FeatherReader, against a counting allocator): the
/// worst shape reaches **210 bytes per counted character**, so 640 000 x 210 B is
/// about 128 MiB. Sweeping nesting depths 10, 50, 100 and 120, the worst is
/// 210.6 B per counted character (at depth 120) and peak equals retained —
/// `serde_json` overshoots by nothing measurable while it builds. Depth cannot be
/// pushed further to raise the ratio: `serde_json`'s own recursion limit of 128
/// refuses a deeper body outright.
///
/// **The floor is real traffic.** The cap is shared with FeatherReader's
/// `listRecords` parser, whose densest legitimate page (100 `readState` records,
/// each with two full id arrays) counts 403 003; FeatherReader's tests hold the
/// cap above that. A DID document or authorization-server metadata document
/// counts in the hundreds.
///
/// Ported from FeatherReader `src/atproto.rs` (`MAX_LIST_STRUCTURAL_CHARS`).
pub const MAX_LIST_STRUCTURAL_CHARS: usize = 640_000;

/// A body refused before parsing for carrying more JSON structure than
/// [`MAX_LIST_STRUCTURAL_CHARS`]. The server answered with something no honest
/// listing or document looks like, so a caller filing failures can treat it as a
/// parse failure rather than a transport one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{what} counts at least {counted} structural characters, over the \
     {MAX_LIST_STRUCTURAL_CHARS} cap — refusing before parsing it"
)]
pub struct StructureExplosion {
    /// What the body was, for the log line.
    pub what: String,
    /// How many structural characters were counted.
    pub counted: usize,
}

/// How many nodes `body` would parse into, to within one, without parsing it.
///
/// **A lower bound.** `[1,2,3]` counts three — one `[` and two commas — and
/// builds four values. The deficit is never more than one (verified exhaustively
/// over every body of length 1-5 from a JSON alphabet), because every node but
/// the outermost is introduced by one of the characters counted here. That is
/// the direction a guard needs: it can under-count by one and still refuse
/// everything it must.
///
/// Counts the structural characters that introduce a value — `{`, `[`, `,`, `:`
/// — **outside strings**, which is what makes this sound: a node cannot appear
/// without one, and a string's contents cannot invent one. Skipping strings is
/// the whole difficulty; counting naively would refuse a legitimate article that
/// happens to contain a million commas.
pub fn count_structural_chars(body: &[u8]) -> usize {
    let mut nodes = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in body {
        if in_string {
            // `\"` stays inside the string; `\\` does not escape the quote that
            // follows it. Getting this pair wrong makes the scan count a whole
            // document as structure, or none of it.
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            // A string is a node, and everything inside it is not.
            b'"' => {
                in_string = true;
                nodes += 1;
            }
            b'{' | b'[' | b',' | b':' => nodes += 1,
            _ => {}
        }
    }
    nodes
}

/// Refuse a body carrying more JSON structure than
/// [`MAX_LIST_STRUCTURAL_CHARS`], with a [`StructureExplosion`] naming `what`.
pub fn refuse_a_structure_explosion(body: &[u8], what: &str) -> Result<()> {
    let counted = count_structural_chars(body);
    if counted > MAX_LIST_STRUCTURAL_CHARS {
        return Err(StructureExplosion {
            what: what.to_string(),
            counted,
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// **The pre-auth path, and the one a stranger can reach.**
    ///
    /// `get_json` returns a `Value` from a host chosen by whoever typed the
    /// handle: `resolve::did_document` fetches a `did:web` document from the host
    /// named in the DID, and `discovery::discover` fetches
    /// `/.well-known/oauth-authorization-server` from the PDS URL that came with
    /// it. Neither needs a session. `read_capped` bounds the wire at 8 MiB, which
    /// is the INPUT to the amplification rather than a limit on it — measured, 824
    /// MB of `Value` for that body — so before the guard a stranger could spend
    /// most of a 512 MB box by submitting a handle.
    ///
    /// Asserts the guard through the real `Fetcher::get_no_redirect` +
    /// `read_capped` path rather than on the helper, because the point is the
    /// wiring.
    #[tokio::test]
    async fn a_did_document_that_is_a_structure_explosion_is_refused() {
        let mut body = String::from(r#"{"id":"did:web:probe.test","service":["#);
        for _ in 0..700_000 {
            body.push_str("{},");
        }
        body.push_str("{}]}");
        assert!(
            count_structural_chars(body.as_bytes()) > MAX_LIST_STRUCTURAL_CHARS,
            "the probe body is not over the cap, so this test proves nothing",
        );
        // `serve_bodies_in_sequence` answers `application/json`, which `DID_JSON`
        // accepts — so the refusal under test is the body's, not `check_meta`'s.
        // The host override is how a loopback server gets past the SSRF guard:
        // without it this fails on the address rather than on the body, which is
        // exactly the "failed for the wrong reason" trap the assertion below
        // exists to catch.
        let base = crate::testing::serve_bodies_in_sequence(vec![body.into_bytes()]).await;
        let port: u16 = base
            .trim_end_matches('/')
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let fetcher = Fetcher::default();
        crate::testing::test_host_override(
            &fetcher,
            "did-explosion.test",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        );
        let err = get_json(
            &fetcher,
            &format!("http://did-explosion.test:{port}/did.json"),
            DID_JSON,
        )
        .await
        .expect_err("a structure explosion was parsed rather than refused");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("structural characters"),
            "failed for the wrong reason: {rendered}"
        );
    }
    use super::*;

    #[test]
    fn a_200_with_json_is_accepted() {
        assert!(check_meta(200, Some("application/json"), JSON).is_ok());
    }

    /// Parameters and casing are both legal on a real content type.
    #[test]
    fn the_media_type_is_compared_without_parameters_or_case() {
        for ct in [
            "application/json; charset=utf-8",
            "application/json;charset=UTF-8",
            "APPLICATION/JSON",
            "  application/json  ",
        ] {
            assert!(check_meta(200, Some(ct), JSON).is_ok(), "rejected {ct:?}");
        }
    }

    /// A server answering HTML is not serving the document we asked for, even if
    /// the bytes would happen to parse.
    #[test]
    fn a_non_json_content_type_is_rejected() {
        for ct in [
            "text/html",
            "text/plain",
            "application/xml",
            "application/jsonp",
            "application/json-seq",
        ] {
            assert!(check_meta(200, Some(ct), JSON).is_err(), "accepted {ct:?}");
        }
    }

    #[test]
    fn a_missing_content_type_is_rejected() {
        assert!(check_meta(200, None, JSON).is_err());
    }

    /// Exactly 200 — a redirect reaching here at all would mean the no-redirect
    /// guard failed, and 2xx-but-not-200 is not a metadata document.
    #[test]
    fn only_status_200_is_accepted() {
        for status in [201u16, 204, 206, 301, 302, 400, 401, 403, 500] {
            assert!(
                check_meta(status, Some("application/json"), JSON).is_err(),
                "accepted status {status}"
            );
        }
    }

    /// DID documents are served as `did+ld+json` by plc.directory; metadata
    /// documents must NOT be.
    #[test]
    fn the_allowed_set_is_per_document_kind() {
        assert!(check_meta(200, Some("application/did+ld+json"), DID_JSON).is_ok());
        assert!(check_meta(200, Some("application/json"), DID_JSON).is_ok());
        assert!(check_meta(200, Some("application/did+ld+json"), JSON).is_err());
    }

    /// These fetches must fail closed on an internal target like every other
    /// outbound call.
    ///
    /// Asserts on the GUARD's error rather than `is_err()`: connecting to
    /// `127.0.0.1` fails regardless, so an `is_err()`-only assertion would pass
    /// with the SSRF guard removed entirely.
    #[tokio::test]
    async fn discovery_fetches_fail_closed_on_internal_targets() {
        let fetcher = Fetcher::default();
        for url in [
            "http://127.0.0.1/.well-known/oauth-authorization-server",
            "http://169.254.169.254/.well-known/oauth-protected-resource",
            "http://10.1.2.3/did.json",
        ] {
            for rendered in [
                format!(
                    "{:#}",
                    get_json(&fetcher, url, JSON).await.expect_err("allowed")
                ),
                format!(
                    "{:#}",
                    get_json_optional(&fetcher, url, JSON)
                        .await
                        .expect_err("allowed")
                ),
            ] {
                assert!(
                    rendered.contains("forbidden (internal) address"),
                    "{url} failed for the wrong reason: {rendered}"
                );
            }
        }
    }

    // ── the structure guard, moved here from FeatherReader's atproto.rs ──────
    //
    // Copies of the two atproto.rs tests that exercise the scanner alone (the
    // others there need FeatherReader's listing parser and lexicons, and stay
    // with it). FeatherReader keeps its own copies.

    /// **An escaped quote does not end the string**, asserted without a magic
    /// number: the same document with the escape replaced by a plain letter has
    /// the same structure, so it must count the same. Get the escape wrong and the
    /// scanner leaves the string early and counts the rest as structure.
    #[test]
    fn an_escaped_quote_does_not_end_the_string() {
        let escaped = br#"{"records":[{"uri":"a\"b","value":{}}],"cursor":"x"}"#;
        let plain = br#"{"records":[{"uri":"axb","value":{}}],"cursor":"x"}"#;
        assert_eq!(
            count_structural_chars(escaped),
            count_structural_chars(plain),
            "an escaped quote changed the structure count"
        );
        let backslash = br#"{"records":[],"cursor":"x\\"}"#;
        let letter = br#"{"records":[],"cursor":"xy"}"#;
        assert_eq!(
            count_structural_chars(backslash),
            count_structural_chars(letter),
            "an escaped backslash changed the structure count"
        );
    }

    /// A string is itself a node, so a page of strings costs more than a page of
    /// numbers. Without that, an array of a million short strings reads as cheap.
    #[test]
    fn a_string_counts_as_a_node() {
        assert!(
            count_structural_chars(br#"["a","b","c"]"#) > count_structural_chars(br#"[1,1,1]"#),
            "strings were not counted, so an array of them looks free"
        );
    }

    /// The refusal is a typed [`StructureExplosion`] in the chain, so a caller
    /// can file it (FeatherReader's feed classifier downcasts to it), and it
    /// names what was refused.
    #[test]
    fn a_refused_body_is_a_structure_explosion_naming_what_it_was() {
        let body = "[".repeat(MAX_LIST_STRUCTURAL_CHARS + 1);
        let err = refuse_a_structure_explosion(body.as_bytes(), "the probe")
            .expect_err("over the cap was accepted");
        let explosion = err
            .downcast_ref::<StructureExplosion>()
            .expect("not a StructureExplosion");
        assert_eq!(explosion.what, "the probe");
        assert_eq!(explosion.counted, MAX_LIST_STRUCTURAL_CHARS + 1);
        assert!(refuse_a_structure_explosion(
            "[".repeat(MAX_LIST_STRUCTURAL_CHARS).as_bytes(),
            "at the cap"
        )
        .is_ok());
    }
}
