//! DPoP-bound XRPC calls against the user's PDS: the transport only.
//!
//! Two properties that are not obvious from the call shapes:
//!
//! * **The PDS comes from the session's `aud`**, never re-derived per call. It
//!   is a property of the token set (a token is valid at one PDS), and a
//!   [`SessionStore`](crate::store::SessionStore) is expected to bind it to the
//!   session so it cannot be repointed.
//! * **Every request carries both the proof and the token.** A resource request
//!   is `Authorization: DPoP <token>` plus a `DPoP` proof whose `ath` binds to
//!   that token; either alone is useless. A PDS's nonce challenge (`401` +
//!   `WWW-Authenticate: DPoP error="use_dpop_nonce"`) is answered once.
//!
//! Ported from FeatherReader `src/oauth/xrpc.rs` (`Repo::url`, `send_raw`,
//! `error_fields`, `rejection` and `xrpc_error`). What is NOT here, and stays
//! the caller's: listing walks and their bounds, record writers, rkey
//! generation, batching of `applyWrites`, and any lexicon's typed surface.

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::dpop::Endpoint;
use crate::keys::SigningKey;
use crate::net::Fetcher;
use crate::request::{self, DpopBody, DpopRequest, PostOutcome, Retry};
use crate::store::{NonceStore, Session};

/// An authenticated handle on one account's repo.
pub struct Repo<'a, N: NonceStore> {
    /// The SSRF-guarded fetcher every request goes through.
    pub fetcher: &'a Fetcher,
    /// Where the PDS's DPoP nonces are kept between requests.
    pub nonces: &'a N,
    /// The session whose `aud` names the PDS and whose access token is sent.
    pub session: &'a Session,
    /// The session's DPoP key, already unsealed.
    pub key: &'a SigningKey,
}

impl<N: NonceStore> Repo<'_, N> {
    /// The XRPC endpoint for a method, on THIS session's PDS.
    pub fn url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{nsid}", self.session.aud.trim_end_matches('/'))
    }

    /// `GET /xrpc/{nsid}?{query}`. A non-2xx is an error whose source is an
    /// [`XrpcError`]; a 2xx is returned as it came, body unparsed.
    ///
    /// `now` is the time at the call (Unix seconds), for the proof's `iat`.
    pub async fn get(&self, nsid: &str, query: &[(&str, &str)], now: i64) -> Result<PostOutcome> {
        let mut url =
            url::Url::parse(&self.url(nsid)).with_context(|| format!("building the {nsid} URL"))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        self.send(url.as_str(), DpopBody::Query, nsid, now).await
    }

    /// `POST /xrpc/{nsid}` with `body` as JSON. A non-2xx is an error whose
    /// source is an [`XrpcError`]; a 2xx is returned as it came, body unparsed
    /// (a 200 with an empty body is legitimate for some procedures).
    ///
    /// `now` is the time at the call (Unix seconds), for the proof's `iat`.
    pub async fn post_json(&self, nsid: &str, body: &Value, now: i64) -> Result<PostOutcome> {
        let bytes = serde_json::to_vec(body)?;
        self.send(&self.url(nsid), DpopBody::Json(bytes), nsid, now)
            .await
    }

    /// Send, and fail loudly on a non-2xx with the XRPC error if there is one.
    async fn send(
        &self,
        url: &str,
        body: DpopBody<'_>,
        nsid: &str,
        now: i64,
    ) -> Result<PostOutcome> {
        let outcome = request::send_with_dpop(
            self.fetcher,
            self.nonces,
            &DpopRequest {
                endpoint: Endpoint::ResourceServer,
                url,
                key: self.key,
                access_token: Some(&self.session.access_token),
                body,
                // A repo call is repeated on a nonce challenge, on the
                // ASSUMPTION that a PDS answering with a challenge has not acted
                // on the request. That is how conformant servers behave and what
                // the reference relies on, but it is not a guarantee we can
                // verify: a PDS or intermediary that emitted `use_dpop_nonce`
                // after a write committed would yield a duplicate record from a
                // non-idempotent procedure such as `createRecord`.
                retry: Retry::Allowed,
            },
            now,
        )
        .await?;

        if !outcome.is_success() {
            // **The rejection as a value**, so a caller that has to tell "the
            // PDS refused this" from "the network broke" can match on more
            // than wording. Its `Display` is the sentence FeatherReader has
            // always logged.
            return Err(XrpcError::from_response(nsid, outcome.status, &outcome.body).into());
        }
        Ok(outcome)
    }
}

/// A PDS's non-2xx answer to an XRPC call.
///
/// Carries the status and the error document's `error` and `message` fields,
/// never the body: on other paths a body holds tokens, and even here it is the
/// server's to fill. `Display` is `"{nsid} failed: status {status}"`, followed
/// by ` ({error}: {message})` or ` ({error})` when the body named its error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrpcError {
    /// The method that was called.
    pub nsid: String,
    /// The HTTP status.
    pub status: u16,
    /// The error document's `error`, or `"Unknown"` when the body is not an
    /// error document (or too large to be worth parsing).
    pub error: String,
    /// The error document's `message`, if it had one.
    pub message: Option<String>,
    /// Whether `error` came from the body, which decides the `Display`.
    named: bool,
}

impl XrpcError {
    /// The error for a `status` answer to `nsid` carrying `body`.
    ///
    /// The body is length-checked before any parse (see
    /// [`crate::MAX_ERROR_BODY`]), and only `error` and `message` are read.
    pub fn from_response(nsid: &str, status: u16, body: &[u8]) -> Self {
        let (error, message, named) = match fields(body) {
            Some((error, message)) => (error, message, true),
            None => ("Unknown".to_string(), None, false),
        };
        Self {
            nsid: nsid.to_string(),
            status,
            error,
            message,
            named,
        }
    }

    /// `status N`, then the error's reason if the body named one: the part of
    /// the sentence after `"{nsid} failed: "`.
    fn summary(&self) -> String {
        let status = self.status;
        match (self.named, &self.message) {
            (false, _) => format!("status {status}"),
            (true, Some(message)) => format!("status {status} ({}: {message})", self.error),
            (true, None) => format!("status {status} ({})", self.error),
        }
    }
}

impl std::fmt::Display for XrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.nsid, self.summary())
    }
}

impl std::error::Error for XrpcError {}

/// An error body's `error`, and its `message` if that is a string.
///
/// **Bounded by length before it is parsed.** A hostile PDS answering a large
/// error instead of a 200 would otherwise get the amplification
/// [`PostOutcome::json`]'s node guard exists to stop, on every failure. An
/// error document is a few dozen bytes; see [`crate::MAX_ERROR_BODY`].
fn fields(body: &[u8]) -> Option<(String, Option<String>)> {
    if !crate::error_body_worth_parsing(body) {
        return None;
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error").and_then(Value::as_str)?;
    let message = value.get("message").and_then(Value::as_str);
    Some((error.to_string(), message.map(str::to_string)))
}

/// Render an XRPC error body for a message: `"{error}: {message}"`, or just
/// `"{error}"`, or `None` when the body names no error (or is too large to be
/// worth parsing).
///
/// Only ever meant for a NON-success, where the body is an error document
/// rather than a token or a record, and even then only the `error` and
/// `message` fields, never the raw bytes.
pub fn error_fields(body: &[u8]) -> Option<String> {
    let (kind, message) = fields(body)?;
    Some(match message {
        Some(message) => format!("{kind}: {message}"),
        None => kind,
    })
}

/// Format an XRPC failure for an error message: `status N (reason)`.
#[cfg(test)]
fn xrpc_error(body: &[u8], status: u16) -> String {
    XrpcError::from_response("", status, body).summary()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Fetcher;
    use crate::store::memory::MemoryNonces;
    use crate::store::NonceStore;
    use crate::testing::{spawn_tls, test_host_override, TestResponse};
    use serde_json::{json, Value};
    use std::collections::HashMap;

    const NOW: i64 = 1_700_000_000;

    /// The TLS test PDS's host (in the test leaf by default).
    const PDS_HOST: &str = "pds-e2e.test";

    fn session() -> Session {
        Session {
            sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            issuer: "https://pds.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: "{}".into(),
            access_token: "tok".into(),
            refresh_token: "ref".into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto".into(),
            expires_at: None,
        }
    }

    fn repo<'a>(
        fetcher: &'a Fetcher,
        nonces: &'a MemoryNonces,
        session: &'a Session,
        key: &'a SigningKey,
    ) -> Repo<'a, MemoryNonces> {
        Repo {
            fetcher,
            nonces,
            session,
            key,
        }
    }

    /// A TLS PDS answering `routes`, a Fetcher that reaches it, and its origin.
    /// The log records every request, head and body.
    async fn pds(
        routes: Vec<(&str, Vec<TestResponse>)>,
    ) -> (
        Fetcher,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let routes: HashMap<String, Vec<TestResponse>> = routes
            .into_iter()
            .map(|(path, replies)| (path.to_string(), replies))
            .collect();
        let (addr, log) = spawn_tls(move |_| routes).await;
        let fetcher = Fetcher::default();
        test_host_override(&fetcher, PDS_HOST, addr);
        (fetcher, format!("https://{PDS_HOST}:{}", addr.port()), log)
    }

    /// One header of one recorded request, by case-insensitive name.
    fn header(raw: &str, name: &str) -> Option<String> {
        let (head, _) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    }

    /// The claims of one recorded request's DPoP proof.
    fn proof_claims(raw: &str) -> Value {
        use base64::Engine as _;
        let proof = header(raw, "dpop").expect("no DPoP header on the request");
        let seg = proof.split('.').nth(1).expect("malformed JWT");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(seg)
            .expect("JWT segment is not base64url");
        serde_json::from_slice(&bytes).expect("JWT segment is not JSON")
    }

    /// `base64url(SHA-256(token))`, computed here rather than by the code under
    /// test.
    fn ath_of(token: &str) -> String {
        use base64::Engine as _;
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// The PDS's resource-server nonce challenge (RFC 9449 §9).
    fn use_dpop_nonce(nonce: &str) -> TestResponse {
        TestResponse::json(401, r#"{"error":"use_dpop_nonce"}"#)
            .with_header("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#)
            .with_header("DPoP-Nonce", nonce)
    }

    /// **The PDS comes from the session**, so a call cannot be pointed at
    /// another host by a caller who passes the wrong base.
    #[tokio::test]
    async fn endpoints_are_built_from_the_sessions_audience() {
        let fetcher = Fetcher::default();
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = "https://pds.example.com/".into();
        let repo = repo(&fetcher, &nonces, &s, &key);
        assert_eq!(
            repo.url("com.atproto.repo.listRecords"),
            "https://pds.example.com/xrpc/com.atproto.repo.listRecords",
            "a trailing slash on the audience must not double the separator"
        );
    }

    /// An XRPC error document is summarised by its `error`/`message` fields
    /// only — never by echoing the raw body, which on other paths holds tokens.
    #[test]
    fn an_xrpc_error_is_summarised_not_echoed() {
        let body = br#"{"error":"InvalidRequest","message":"unknown collection"}"#;
        let rendered = xrpc_error(body, 400);
        assert!(rendered.contains("InvalidRequest"));
        assert!(rendered.contains("unknown collection"));

        // A body that is not an XRPC error contributes nothing but the status.
        let opaque = xrpc_error(br#"{"access_token":"SECRET"}"#, 500);
        assert_eq!(opaque, "status 500");
        assert!(!opaque.contains("SECRET"));
        assert_eq!(xrpc_error(b"<html>oops</html>", 502), "status 502");
    }

    /// Every repo call must fail closed on an internal target, like every other
    /// outbound path — asserted on the guard's own error.
    #[tokio::test]
    async fn repo_calls_fail_closed_on_an_internal_pds() {
        let fetcher = Fetcher::default();
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = "http://127.0.0.1:2583".into();
        let repo = repo(&fetcher, &nonces, &s, &key);

        let err = repo
            .get(
                "com.atproto.repo.listRecords",
                &[("repo", &s.sub), ("collection", "app.feather.subscription")],
                NOW,
            )
            .await
            .expect_err("must refuse a loopback PDS");
        assert!(
            format!("{err:#}").contains("forbidden (internal) address"),
            "failed for the wrong reason: {err:#}"
        );
    }

    #[test]
    fn an_oversized_error_body_is_not_parsed_for_its_reason() {
        let small = br#"{"error":"InvalidSwap","message":"record changed"}"#;
        assert_eq!(
            error_fields(small).as_deref(),
            Some("InvalidSwap: record changed"),
            "a real error body must still render its reason",
        );

        let mut huge = String::from(r#"{"error":"InvalidSwap","pad":["#);
        while huge.len() < crate::MAX_ERROR_BODY + 1_024 {
            huge.push_str("{},");
        }
        huge.push_str("{}]}");
        assert!(huge.len() > crate::MAX_ERROR_BODY);
        assert_eq!(
            error_fields(huge.as_bytes()),
            None,
            "an oversized error body was deserialised to fish out one string",
        );
    }

    /// **A PDS rejection is structured, not only a sentence (#241).**
    ///
    /// The read-state flusher has to tell "the PDS refused this batch" from "the
    /// network broke". The rendered message must not change: it is what every
    /// existing log line and assertion reads.
    #[tokio::test]
    async fn a_rejected_write_carries_the_status_and_error_name() {
        let (fetcher, origin, _) = pds(vec![(
            "/xrpc/com.atproto.repo.applyWrites",
            vec![TestResponse::json(
                500,
                json!({ "error": "InternalServerError", "message": "Internal Server Error" })
                    .to_string(),
            )],
        )])
        .await;
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = origin;
        let repo = repo(&fetcher, &nonces, &s, &key);

        let err = repo
            .post_json(
                "com.atproto.repo.applyWrites",
                &json!({
                    "repo": s.sub,
                    "writes": [{
                        "$type": "com.atproto.repo.applyWrites#delete",
                        "collection": "community.lexicon.rss.readState",
                        "rkey": "rs-0",
                    }],
                }),
                NOW,
            )
            .await
            .expect_err("a 500 is a failure");
        assert_eq!(
            err.to_string(),
            "com.atproto.repo.applyWrites failed: status 500 \
             (InternalServerError: Internal Server Error)",
            "the rendered message changed",
        );
        let xrpc = err
            .chain()
            .find_map(|cause| cause.downcast_ref::<XrpcError>());
        match xrpc {
            Some(XrpcError { status, error, .. }) => {
                assert_eq!(*status, 500);
                assert_eq!(error, "InternalServerError");
            }
            other => panic!("no structured XRPC error in the chain: {other:?}"),
        }
    }

    /// **A resource server's nonce challenge is answered once.** A PDS signals
    /// it with `401` + `WWW-Authenticate: DPoP error="use_dpop_nonce"` (RFC 9449
    /// §9), not the authorization server's `400` body; the request is sent again
    /// with the offered nonce in its proof, still bound to the token.
    #[tokio::test]
    async fn a_resource_request_answers_the_header_nonce_challenge_once() {
        let (fetcher, origin, log) = pds(vec![(
            // The test server routes on the whole request target, query included.
            "/xrpc/com.atproto.repo.describeRepo?repo=did%3Aplc%3Aewvi7nxzyoun6zhxrhs64oiz",
            vec![
                use_dpop_nonce("pds-nonce-1"),
                TestResponse::json(200, r#"{"handle":"alice.test"}"#),
            ],
        )])
        .await;
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = origin.clone();
        let repo = repo(&fetcher, &nonces, &s, &key);

        let outcome = repo
            .get("com.atproto.repo.describeRepo", &[("repo", &s.sub)], NOW)
            .await
            .expect("the challenge was answered");
        assert_eq!(outcome.status, 200);
        assert_eq!(outcome.json().unwrap()["handle"], "alice.test");

        let sent = log.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "one challenge, one retry: {sent:?}");
        let first = proof_claims(&sent[0]);
        let second = proof_claims(&sent[1]);
        assert!(first.get("nonce").is_none(), "no nonce was known yet");
        assert_eq!(
            second["nonce"], "pds-nonce-1",
            "the retry ignored the nonce"
        );
        assert_eq!(
            second["ath"],
            ath_of("tok"),
            "the retry dropped the token binding"
        );
        assert_ne!(first["jti"], second["jti"], "a retry is a fresh proof");
        assert_eq!(
            header(&sent[1], "authorization").as_deref(),
            Some("DPoP tok"),
            "the retry dropped the token",
        );
        assert_eq!(
            nonces.get(&origin).await.unwrap().as_deref(),
            Some("pds-nonce-1"),
            "the PDS's nonce was not kept for the next request",
        );
    }

    /// **And only once.** A PDS that challenges every request gets the request
    /// and one retry, and the caller sees the 401 as a rejection.
    #[tokio::test]
    async fn a_pds_that_always_challenges_gets_exactly_two_requests() {
        let (fetcher, origin, log) = pds(vec![(
            "/xrpc/com.atproto.repo.createRecord",
            vec![
                use_dpop_nonce("n-1"),
                use_dpop_nonce("n-2"),
                use_dpop_nonce("n-3"),
                TestResponse::json(200, "{}"),
            ],
        )])
        .await;
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = origin;
        let repo = repo(&fetcher, &nonces, &s, &key);

        let err = repo
            .post_json("com.atproto.repo.createRecord", &json!({}), NOW)
            .await
            .expect_err("a 401 is a failure");
        assert_eq!(log.lock().unwrap().len(), 2, "the retry is bounded at one");
        let xrpc = err.downcast_ref::<XrpcError>().expect("structured");
        assert_eq!(xrpc.status, 401);
        assert_eq!(xrpc.error, "use_dpop_nonce");
    }

    /// **Every request carries both the proof and the token, bound together.**
    /// The proof's `ath` is `base64url(SHA-256(access_token))`, its `htm` and
    /// `htu` name this request (the query is not part of `htu`), and the token
    /// rides as `Authorization: DPoP`, never `Bearer`.
    #[tokio::test]
    async fn a_resource_proof_binds_the_access_token() {
        let (fetcher, origin, log) = pds(vec![
            (
                "/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aewvi7nxzyoun6zhxrhs64oiz\
                 &collection=c&rkey=a+b%26c",
                vec![TestResponse::json(200, "{}")],
            ),
            (
                "/xrpc/com.atproto.repo.putRecord",
                vec![TestResponse::json(200, "{}")],
            ),
        ])
        .await;
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let mut s = session();
        s.aud = format!("{origin}/");
        s.access_token = "access-token-under-test".into();
        let repo = repo(&fetcher, &nonces, &s, &key);

        repo.get(
            "com.atproto.repo.getRecord",
            &[("repo", &s.sub), ("collection", "c"), ("rkey", "a b&c")],
            NOW,
        )
        .await
        .expect("get");
        repo.post_json("com.atproto.repo.putRecord", &json!({ "rkey": "r" }), NOW)
            .await
            .expect("post");

        let sent = log.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(
            sent[0].starts_with(
                "GET /xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aewvi7nxzyoun6zhxrhs64oiz\
                 &collection=c&rkey=a+b%26c "
            ),
            "the query was not encoded onto the URL: {}",
            sent[0]
        );
        assert!(sent[1].starts_with("POST /xrpc/com.atproto.repo.putRecord "));
        assert_eq!(
            header(&sent[1], "content-type").as_deref(),
            Some("application/json")
        );
        let (_, body) = sent[1].split_once("\r\n\r\n").unwrap();
        assert_eq!(serde_json::from_str::<Value>(body).unwrap()["rkey"], "r");

        for (raw, htm, nsid) in [
            (&sent[0], "GET", "com.atproto.repo.getRecord"),
            (&sent[1], "POST", "com.atproto.repo.putRecord"),
        ] {
            let claims = proof_claims(raw);
            assert_eq!(claims["ath"], ath_of("access-token-under-test"), "{claims}");
            assert_eq!(claims["htm"], htm);
            assert_eq!(claims["htu"], format!("{origin}/xrpc/{nsid}"));
            assert_eq!(claims["iat"], NOW);
            assert_eq!(
                header(raw, "authorization").as_deref(),
                Some("DPoP access-token-under-test")
            );
        }
    }

    /// The error's own `Display` is the whole sentence, so a caller that
    /// formats only the typed value (not the anyhow chain) reads the same words;
    /// and a body that names no error keeps "Unknown" out of the sentence.
    #[test]
    fn an_xrpc_error_renders_the_same_sentence_as_its_summary() {
        let named = XrpcError::from_response(
            "com.atproto.repo.applyWrites",
            500,
            br#"{"error":"InternalServerError","message":"Internal Server Error"}"#,
        );
        assert_eq!(
            named.to_string(),
            "com.atproto.repo.applyWrites failed: status 500 \
             (InternalServerError: Internal Server Error)"
        );
        assert_eq!(named.message.as_deref(), Some("Internal Server Error"));

        let bare = XrpcError::from_response("x.y", 400, br#"{"error":"InvalidSwap"}"#);
        assert_eq!(bare.to_string(), "x.y failed: status 400 (InvalidSwap)");
        assert_eq!(bare.message, None);

        let opaque = XrpcError::from_response("x.y", 502, br#"{"access_token":"SECRET"}"#);
        assert_eq!(opaque.to_string(), "x.y failed: status 502");
        assert_eq!(opaque.error, "Unknown");
        assert!(!format!("{opaque:?}").contains("SECRET"));

        // A body that really names its error "Unknown" still says so.
        let literal = XrpcError::from_response("x.y", 400, br#"{"error":"Unknown"}"#);
        assert_eq!(literal.to_string(), "x.y failed: status 400 (Unknown)");
    }

    /// A caller can hold these futures across a `tokio::spawn`, for any
    /// [`NonceStore`].
    #[test]
    fn the_repo_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn generic<N: NonceStore>(repo: &Repo<'_, N>) {
            assert_send(&repo.get("x.y", &[("a", "b")], NOW));
            assert_send(&repo.post_json("x.y", &json!({}), NOW));
        }
        let fetcher = Fetcher::default();
        let nonces = MemoryNonces::new();
        let key = SigningKey::generate("k");
        let s = session();
        generic(&repo(&fetcher, &nonces, &s, &key));
    }
}
