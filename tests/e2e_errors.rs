//! **The error messages callers match on**, and the typed values behind them.
//!
//! FeatherReader branches on calamus's errors by their TEXT today
//! (`format!("{err:#}").contains(...)` in its web, repo, feed and oauth tests,
//! and one exact `to_string()` on an XRPC failure). The table in
//! [`error_messages_callers_match_on_are_stable`] pins every one of those
//! messages, each produced through calamus's real code path (the fake
//! authorization server, PDS and PLC directory where a server is needed), so
//! a change to any of them fails here before it reaches a caller.
//!
//! `typed` is the other half: each decision a caller branches on is a
//! `calamus::Error` variant reachable from the `anyhow::Error` with
//! `calamus::Error::find`, so no caller has to match on text.
//!
//! Needs `test-util` (the fake), `revoke` (`sign_out`) and `xrpc` (`Repo`).

mod common;

use std::time::Duration;

use calamus::flow::CallbackParams;
use calamus::keys::SigningKey;
use calamus::net::{FetchPolicy, Fetcher};
use calamus::revoke::{sign_out, Revocation, RevokeContext};
use calamus::session::{valid_session, RefreshLocks};
use calamus::store::SessionStore;
use calamus::testing::fake::{HANDLE, OTHER_AS_HOST};
use calamus::xrpc::Repo;
use common::{World, NOW};

/// Late enough that a fresh login's session is stale.
const LATER: i64 = NOW + 4000;

/// A DID other than the fake account's, well-formed.
const OTHER_DID: &str = "did:plc:someoneelseaaaaaaaaaaaaa";

/// One way a caller reaches an error it matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// `Fetcher::get_without_hop_policy` of an internal IP literal.
    FetchInternalLiteral,
    /// `Fetcher::get_without_hop_policy` of a name that resolves to loopback.
    FetchInternalName,
    /// `sign_out` against a revocation endpoint on an internal address.
    RevokeAtInternalAddress,
    /// A listing body with more JSON structure than the cap.
    StructureExplosion,
    /// `jwt::verify` of a token that is not three segments.
    JwsTwoSegments,
    /// `jwt::verify` of an `HS256` token.
    JwsHs256,
    /// Re-discovery after the PDS names another authorization server.
    MixUpOnRediscovery,
    /// A refresh whose session is signed out while its request is in flight.
    SignedOutMidRefresh,
    /// A callback presenting another browser's binding cookie.
    ForeignBrowser,
    /// A callback whose `state` no pending login holds.
    UnknownState,
    /// A callback whose `iss` is another issuer's.
    IssParameterMismatch,
    /// A callback carrying `error=access_denied`.
    AccessDenied,
    /// An `http://` issuer.
    IssuerNotHttps,
    /// Authorization-server metadata with a token endpoint on another origin.
    EndpointOffOrigin,
    /// A login started for a handle under a reserved TLD.
    ReservedTld,
    /// A sign-out at an authorization server with no revocation endpoint.
    NoRevocationEndpoint,
    /// A sign-out at a server that does not answer within the deadline.
    RevokeDeadline,
    /// `applyWrites` answered `500 InternalServerError` by the PDS.
    ApplyWrites500,
    /// A token exchange answering for another DID.
    SubjectMismatch,
    /// A token exchange answered `400`.
    TokenExchange400,
    /// A pushed authorization request answered `400`.
    Par400,
    /// A refresh presenting a spent refresh token.
    InvalidGrant,
    /// A refresh answered `503`.
    Refresh503,
    /// `private_key_jwt` credentials with no assertion.
    NoClientAssertion,
    /// A DID document fetch the directory answers with a redirect.
    RedirectedDidDocument,
    /// `try_revoke` at an authorization server with no revocation endpoint.
    TryRevokeNoEndpoint,
}

/// What a trigger produced: an error, or a revocation's reason (sign-out is
/// never an `Err`; callers match on `Revocation::Failed`'s text).
enum Outcome {
    Err(anyhow::Error),
    Revocation(Revocation),
}

impl Outcome {
    fn err(self) -> anyhow::Error {
        match self {
            Outcome::Err(err) => err,
            Outcome::Revocation(r) => panic!("expected an error, got {r:?}"),
        }
    }

    /// As callers render it: `{err:#}` for an error, the reason for a
    /// revocation.
    fn rendered(&self) -> String {
        match self {
            Outcome::Err(err) => format!("{err:#}"),
            Outcome::Revocation(Revocation::Failed(reason))
            | Outcome::Revocation(Revocation::LeftInPlace(reason)) => reason.clone(),
            Outcome::Revocation(other) => format!("{other:?}"),
        }
    }

    /// The top-level message alone (`err.to_string()`).
    fn top(&self) -> String {
        match self {
            Outcome::Err(err) => err.to_string(),
            Outcome::Revocation(_) => self.rendered(),
        }
    }
}

fn expect_err<T: std::fmt::Debug>(result: anyhow::Result<T>, what: &str) -> Outcome {
    match result {
        Ok(v) => panic!("{what}: expected an error, got {v:?}"),
        Err(err) => Outcome::Err(err),
    }
}

fn revoke_context<'a>(
    w: &'a World,
    issuer: &'a str,
    endpoint: Option<&'a str>,
    deadline: Duration,
) -> RevokeContext<'a> {
    RevokeContext {
        revocation_endpoint: endpoint,
        client_id: w.client.client_id(),
        auth_method: w.client.auth_method(),
        client_key: w.client.key(),
        deadline,
        issuer,
    }
}

/// A started and approved login's callback parameters and binding token.
async fn approved(w: &World) -> (CallbackParams, String) {
    let started = w.start(HANDLE).await.expect("the login starts");
    let params = w.fake.approve(&started.authorize_url).unwrap();
    (params, started.binding_token)
}

/// Run `trigger` through calamus's real code path.
async fn run(trigger: Trigger) -> Outcome {
    match trigger {
        Trigger::FetchInternalLiteral => {
            let fetcher = Fetcher::new(FetchPolicy::default()).unwrap();
            expect_err(
                fetcher
                    .get_without_hop_policy("http://127.0.0.1/", &[])
                    .await
                    .map(|_| ()),
                "loopback literal",
            )
        }
        Trigger::FetchInternalName => {
            let fetcher = Fetcher::new(FetchPolicy::default()).unwrap();
            expect_err(
                fetcher
                    .get_without_hop_policy("http://localhost/", &[])
                    .await
                    .map(|_| ()),
                "loopback name",
            )
        }
        Trigger::RevokeAtInternalAddress => {
            let w = World::new().await;
            let login = w.login().await;
            let ctx = revoke_context(
                &w,
                &login.session.issuer,
                Some("https://127.0.0.1/revoke"),
                Duration::from_secs(5),
            );
            Outcome::Revocation(
                sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await,
            )
        }
        Trigger::StructureExplosion => {
            let body = vec![b'['; calamus::fetch::MAX_LIST_STRUCTURAL_CHARS + 1];
            expect_err(
                calamus::fetch::refuse_a_structure_explosion(&body, "listRecords page"),
                "structure explosion",
            )
        }
        Trigger::JwsTwoSegments => {
            let key = SigningKey::generate("k");
            expect_err(calamus::jwt::verify(&key, "a.b"), "two segments")
        }
        Trigger::JwsHs256 => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let key = SigningKey::generate("k");
            let jws = format!(
                "{}.{}.{}",
                b64.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
                b64.encode(br#"{}"#),
                b64.encode([0u8; 32]),
            );
            expect_err(calamus::jwt::verify(&key, &jws), "HS256")
        }
        Trigger::MixUpOnRediscovery => {
            let w = World::new().await;
            let login = w.login().await;
            w.fake.point_pds_at(OTHER_AS_HOST);
            expect_err(w.discover_for(&login.session).await, "mix-up")
        }
        Trigger::SignedOutMidRefresh => {
            let w = World::new().await;
            let login = w.login().await;
            let server = w.discover_for(&login.session).await.unwrap();
            let ctx = w.refresh_context(&server);
            let locks = RefreshLocks::default();
            w.fake.stall_next(Duration::from_millis(500));
            let (refreshed, ()) = tokio::join!(
                valid_session(
                    &w.sessions,
                    &w.fetcher,
                    &w.nonces,
                    &locks,
                    &login.did,
                    &ctx,
                    LATER,
                ),
                async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    w.sessions.delete(&login.did).await.unwrap();
                },
            );
            expect_err(refreshed, "signed out mid-refresh")
        }
        Trigger::ForeignBrowser => {
            let w = World::new().await;
            let (params, _) = approved(&w).await;
            expect_err(
                w.client
                    .complete(&w.deps(), &params, Some("another-browsers-token"), NOW)
                    .await,
                "foreign browser",
            )
        }
        Trigger::UnknownState => {
            let w = World::new().await;
            let (mut params, binding) = approved(&w).await;
            params.state = Some("no-such-state".into());
            expect_err(
                w.client
                    .complete(&w.deps(), &params, Some(&binding), NOW)
                    .await,
                "unknown state",
            )
        }
        Trigger::IssParameterMismatch => {
            let w = World::new().await;
            let (mut params, binding) = approved(&w).await;
            params.iss = Some(w.fake.origin(OTHER_AS_HOST));
            expect_err(
                w.client
                    .complete(&w.deps(), &params, Some(&binding), NOW)
                    .await,
                "iss mismatch",
            )
        }
        Trigger::AccessDenied => {
            let w = World::new().await;
            let (mut params, binding) = approved(&w).await;
            params.code = None;
            params.error = Some("access_denied".into());
            expect_err(
                w.client
                    .complete(&w.deps(), &params, Some(&binding), NOW)
                    .await,
                "access denied",
            )
        }
        Trigger::IssuerNotHttps => expect_err(
            calamus::discovery::validate_issuer_form("http://as.example.com"),
            "http issuer",
        ),
        Trigger::EndpointOffOrigin => {
            let w = World::new().await;
            let fetcher = &w.fetcher;
            let found = calamus::discovery::discover_with(
                |url| async move {
                    let mut doc =
                        calamus::fetch::get_json(fetcher, &url, calamus::fetch::JSON).await?;
                    if url.ends_with("/.well-known/oauth-authorization-server") {
                        doc["token_endpoint"] = "https://elsewhere.test/token".into();
                    }
                    Ok(doc)
                },
                &w.fake.pds_url(),
                w.client.auth_method().as_str(),
                None,
            )
            .await;
            expect_err(found, "off-origin endpoint")
        }
        Trigger::ReservedTld => {
            let w = World::new().await;
            expect_err(w.start("alice.local").await, "reserved TLD")
        }
        Trigger::NoRevocationEndpoint => {
            let w = World::new().await;
            let login = w.login().await;
            w.fake.advertise_revocation(false);
            let server = w.discover_for(&login.session).await.unwrap();
            let ctx = revoke_context(
                &w,
                &server.issuer,
                server.revocation_endpoint.as_deref(),
                Duration::from_secs(5),
            );
            Outcome::Revocation(
                sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await,
            )
        }
        Trigger::RevokeDeadline => {
            let w = World::new().await;
            let login = w.login().await;
            let server = w.discover_for(&login.session).await.unwrap();
            let ctx = revoke_context(
                &w,
                &server.issuer,
                server.revocation_endpoint.as_deref(),
                Duration::from_millis(300),
            );
            w.fake.stall_next(Duration::from_secs(30));
            Outcome::Revocation(
                sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await,
            )
        }
        Trigger::ApplyWrites500 => {
            let w = World::new().await;
            let login = w.login().await;
            let key = SigningKey::from_jwk_json(&login.session.dpop_key_jwk, "session").unwrap();
            let repo = Repo {
                fetcher: &w.fetcher,
                nonces: &w.nonces,
                session: &login.session,
                key: &key,
            };
            w.fake.fail_next_xrpc_with(
                500,
                serde_json::json!({
                    "error": "InternalServerError",
                    "message": "Internal Server Error",
                }),
            );
            expect_err(
                repo.post_json(
                    "com.atproto.repo.applyWrites",
                    &serde_json::json!({"repo": login.did, "writes": []}),
                    NOW,
                )
                .await,
                "applyWrites 500",
            )
        }
        Trigger::SubjectMismatch => {
            let w = World::new().await;
            w.fake.set_sub(Some(OTHER_DID));
            let (params, binding) = approved(&w).await;
            expect_err(
                w.client
                    .complete(&w.deps(), &params, Some(&binding), NOW)
                    .await,
                "sub mismatch",
            )
        }
        Trigger::TokenExchange400 => {
            let w = World::new().await;
            let (params, binding) = approved(&w).await;
            w.fake.fail_next_with(400);
            expect_err(
                w.client
                    .complete(&w.deps(), &params, Some(&binding), NOW)
                    .await,
                "token 400",
            )
        }
        Trigger::Par400 => {
            let w = World::new().await;
            w.fake.fail_next_with(400);
            expect_err(w.start(HANDLE).await, "PAR 400")
        }
        Trigger::InvalidGrant => {
            let w = World::new().await;
            let login = w.login().await;
            let server = w.discover_for(&login.session).await.unwrap();
            let ctx = w.refresh_context(&server);
            let locks = RefreshLocks::default();
            valid_session(
                &w.sessions,
                &w.fetcher,
                &w.nonces,
                &locks,
                &login.did,
                &ctx,
                LATER,
            )
            .await
            .expect("the first refresh succeeds");
            // A stale copy presents the spent refresh token again.
            w.sessions.put(&login.session).await.unwrap();
            expect_err(
                valid_session(
                    &w.sessions,
                    &w.fetcher,
                    &w.nonces,
                    &locks,
                    &login.did,
                    &ctx,
                    LATER,
                )
                .await,
                "invalid_grant",
            )
        }
        Trigger::Refresh503 => {
            let w = World::new().await;
            let login = w.login().await;
            let server = w.discover_for(&login.session).await.unwrap();
            w.fake.fail_next_with(503);
            expect_err(
                valid_session(
                    &w.sessions,
                    &w.fetcher,
                    &w.nonces,
                    &RefreshLocks::default(),
                    &login.did,
                    &w.refresh_context(&server),
                    LATER,
                )
                .await,
                "refresh 503",
            )
        }
        Trigger::NoClientAssertion => expect_err(
            calamus::client_auth::credential_params(
                calamus::client_auth::AuthMethod::PrivateKeyJwt,
                "https://client.example/metadata.json",
                None,
            ),
            "no assertion",
        ),
        Trigger::RedirectedDidDocument => {
            let w = World::new().await;
            w.fake.redirect_did_documents(true);
            expect_err(w.start(&w.fake.did()).await, "redirected DID document")
        }
        Trigger::TryRevokeNoEndpoint => {
            let w = World::new().await;
            let login = w.login().await;
            let ctx = revoke_context(&w, &login.session.issuer, None, Duration::from_secs(5));
            expect_err(
                calamus::revoke::try_revoke(&w.fetcher, &w.nonces, &ctx, &login.session, NOW).await,
                "no endpoint",
            )
        }
    }
}

/// **Every message a caller matches on, pinned.** Each row is the trigger and
/// the text FeatherReader looks for (where it looks, in the comment). A row
/// failing means a caller's `contains` stopped matching.
mod error_messages_callers_match_on_are_stable {
    use super::*;

    /// How a row's text is compared.
    enum Expect {
        /// `{err:#}` (or the revocation reason) contains it.
        Contains(&'static str),
        /// `err.to_string()` is exactly it.
        Exactly(&'static str),
    }
    use Expect::{Contains, Exactly};

    const TABLE: &[(Trigger, Expect)] = &[
        // revoke.rs, xrpc.rs: `forbidden (internal) address`.
        (
            Trigger::FetchInternalLiteral,
            Contains("forbidden (internal) address"),
        ),
        // atproto.rs, net.rs, network.rs: `forbidden` || `internal`.
        (Trigger::FetchInternalName, Contains("forbidden")),
        (
            Trigger::RevokeAtInternalAddress,
            Contains("forbidden (internal) address"),
        ),
        // atproto.rs, xrpc.rs.
        (
            Trigger::StructureExplosion,
            Contains("structural characters"),
        ),
        // jwt.rs.
        (Trigger::JwsTwoSegments, Contains("expected 3 segments")),
        (Trigger::JwsHs256, Contains("unsupported JWS alg")),
        // discovery.rs, login.rs, revoke.rs: both halves.
        (
            Trigger::MixUpOnRediscovery,
            Contains("different authorization server"),
        ),
        (
            Trigger::MixUpOnRediscovery,
            Contains("refusing to send credentials"),
        ),
        // session.rs.
        (
            Trigger::SignedOutMidRefresh,
            Contains("signed out while being refreshed"),
        ),
        // flow.rs.
        (Trigger::ForeignBrowser, Contains("browser-binding")),
        (Trigger::UnknownState, Contains("no pending login")),
        (Trigger::IssParameterMismatch, Contains("`iss`")),
        (Trigger::AccessDenied, Contains("access_denied")),
        // discovery.rs, login.rs, revoke.rs.
        (Trigger::IssuerNotHttps, Contains("must be https")),
        (Trigger::EndpointOffOrigin, Contains("issuer's own origin")),
        // resolve.rs.
        (Trigger::ReservedTld, Contains("reserved TLD")),
        // revoke.rs.
        (
            Trigger::NoRevocationEndpoint,
            Contains("no revocation endpoint"),
        ),
        (Trigger::RevokeDeadline, Contains("did not finish within")),
        // xrpc.rs: the one exact-string assertion.
        (
            Trigger::ApplyWrites500,
            Exactly(
                "com.atproto.repo.applyWrites failed: status 500 \
                 (InternalServerError: Internal Server Error)",
            ),
        ),
        // login.rs.
        (Trigger::SubjectMismatch, Contains("different subject")),
        (
            Trigger::TokenExchange400,
            Contains("failed with status 400"),
        ),
        (Trigger::Par400, Contains("failed with status 400")),
        // session.rs, e2e_refresh.rs.
        (Trigger::InvalidGrant, Contains("invalid_grant")),
        (Trigger::Refresh503, Contains("failed transiently")),
        // revoke.rs.
        (
            Trigger::NoClientAssertion,
            Contains("requires a client assertion"),
        ),
        // net.rs, e2e_login.rs.
        (
            Trigger::RedirectedDidDocument,
            Contains("refusing to follow a 302"),
        ),
    ];

    #[tokio::test]
    async fn every_pinned_message_is_still_produced() {
        let mut failures = Vec::new();
        for (trigger, expect) in TABLE {
            let outcome = run(*trigger).await;
            match expect {
                Contains(want) => {
                    let got = outcome.rendered();
                    if !got.contains(want) {
                        failures.push(format!("{trigger:?}: {want:?} not in {got:?}"));
                    }
                }
                Exactly(want) => {
                    let got = outcome.top();
                    if got != *want {
                        failures.push(format!("{trigger:?}: {got:?} != {want:?}"));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "messages callers match on changed:\n{}",
            failures.join("\n")
        );
    }
}

/// **Each decision a caller branches on is a typed [`calamus::Error`]**,
/// found in the `anyhow::Error` with [`calamus::Error::find`] however much
/// context a caller has added, and rendering exactly as before.
mod typed {
    use super::*;
    use calamus::error::{
        CallbackError, DiscoveryError, Grant, HandleProblem, RedirectRefusal, ResolutionError,
        RevokeError, SessionGone, TokenError,
    };
    use calamus::token::RefreshFailure;
    use calamus::Error;

    /// The typed error behind `trigger`, or a panic naming what was there.
    async fn typed(trigger: Trigger) -> (anyhow::Error, String) {
        let err = run(trigger).await.err();
        let rendered = format!("{err:#}");
        (err, rendered)
    }

    fn find(err: &anyhow::Error) -> &Error {
        Error::find(err).unwrap_or_else(|| panic!("no calamus::Error in {err:#}"))
    }

    #[tokio::test]
    async fn an_ssrf_refusal_is_an_ssrf_error() {
        let (err, _) = typed(Trigger::FetchInternalLiteral).await;
        match find(&err) {
            Error::Ssrf { host, ip } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(ip.to_string(), "127.0.0.1");
            }
            other => panic!("{other:?}"),
        }
        let (err, _) = typed(Trigger::FetchInternalName).await;
        match find(&err) {
            Error::Ssrf { host, ip } => {
                assert_eq!(host, "localhost");
                assert!(ip.is_loopback(), "{ip}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_refused_redirect_is_redirect_refused() {
        let (err, rendered) = typed(Trigger::RedirectedDidDocument).await;
        match find(&err) {
            Error::RedirectRefused {
                status,
                url,
                refusal,
            } => {
                assert_eq!(*status, 302);
                assert!(
                    url.contains(&calamus::testing::fake::PLC_HOST.to_string()),
                    "{url}"
                );
                assert_eq!(*refusal, RedirectRefusal::NotFollowed);
            }
            other => panic!("{other:?}"),
        }
        assert!(
            rendered.contains("refusing to follow a 302 Found redirect"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn a_reserved_tld_is_an_invalid_handle() {
        let (err, _) = typed(Trigger::ReservedTld).await;
        match find(&err) {
            Error::Resolution(ResolutionError::InvalidHandle { handle, problem }) => {
                assert_eq!(handle, "alice.local");
                assert_eq!(*problem, HandleProblem::ReservedTld("local".into()));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_mix_up_is_an_issuer_mismatch() {
        let w = World::new().await;
        let login = w.login().await;
        w.fake.point_pds_at(OTHER_AS_HOST);
        let err = w.discover_for(&login.session).await.unwrap_err();
        match find(&err) {
            Error::Discovery(DiscoveryError::IssuerMismatch {
                discovered,
                expected,
            }) => {
                assert_eq!(discovered, &w.fake.origin(OTHER_AS_HOST));
                assert_eq!(expected, &login.session.issuer);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_off_origin_endpoint_is_endpoint_off_origin() {
        let (err, _) = typed(Trigger::EndpointOffOrigin).await;
        match find(&err) {
            Error::Discovery(DiscoveryError::EndpointOffOrigin { field, url, .. }) => {
                assert_eq!(field, "token_endpoint");
                assert_eq!(url, "https://elsewhere.test/token");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unknown_state_is_no_pending_login() {
        let (err, _) = typed(Trigger::UnknownState).await;
        assert!(
            matches!(find(&err), Error::Callback(CallbackError::NoPendingLogin)),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_foreign_browser_is_a_binding_mismatch() {
        let (err, _) = typed(Trigger::ForeignBrowser).await;
        assert!(
            matches!(find(&err), Error::Callback(CallbackError::BindingMismatch)),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_foreign_iss_is_an_issuer_parameter_mismatch() {
        let w = World::new().await;
        let (mut params, binding) = approved(&w).await;
        params.iss = Some(w.fake.origin(OTHER_AS_HOST));
        let err = w
            .client
            .complete(&w.deps(), &params, Some(&binding), NOW)
            .await
            .unwrap_err();
        match find(&err) {
            Error::Callback(CallbackError::IssuerParameterMismatch { got, expected }) => {
                assert_eq!(got, &w.fake.origin(OTHER_AS_HOST));
                assert_eq!(expected, &w.fake.issuer());
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_denial_is_a_server_error_with_its_slug() {
        let (err, _) = typed(Trigger::AccessDenied).await;
        assert!(
            matches!(
                find(&err),
                Error::Callback(CallbackError::ServerError("access_denied"))
            ),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_sub_mismatch_is_a_subject_mismatch() {
        let w = World::new().await;
        w.fake.set_sub(Some(OTHER_DID));
        let (params, binding) = approved(&w).await;
        let err = w
            .client
            .complete(&w.deps(), &params, Some(&binding), NOW)
            .await
            .unwrap_err();
        match find(&err) {
            Error::Token(TokenError::SubjectMismatch {
                expected,
                returned,
                during,
            }) => {
                assert_eq!(expected, &w.fake.did());
                assert_eq!(returned, OTHER_DID);
                assert_eq!(*during, Grant::Authorization);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_rejected_exchange_is_exchange_failed_with_its_status() {
        let (err, _) = typed(Trigger::TokenExchange400).await;
        assert!(
            matches!(
                find(&err),
                Error::Token(TokenError::ExchangeFailed { status: 400 })
            ),
            "{err:#}"
        );
        let (err, _) = typed(Trigger::Par400).await;
        assert!(
            matches!(
                find(&err),
                Error::Token(TokenError::ParFailed { status: 400 })
            ),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn invalid_grant_is_a_refresh_failure_that_invalidates() {
        let w = World::new().await;
        let (err, _) = typed(Trigger::InvalidGrant).await;
        match find(&err) {
            e @ Error::Refresh {
                failure,
                sub,
                status,
            } => {
                assert_eq!(*failure, RefreshFailure::SessionInvalid);
                assert_eq!(sub, &w.fake.did());
                assert_eq!(*status, 400);
                assert!(e.invalidates_session());
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_5xx_refresh_is_a_transient_refresh_failure() {
        let (err, _) = typed(Trigger::Refresh503).await;
        match find(&err) {
            e @ Error::Refresh {
                failure, status, ..
            } => {
                assert_eq!(*failure, RefreshFailure::Transient);
                assert_eq!(*status, 503);
                assert!(!e.invalidates_session());
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_session_signed_out_mid_refresh_is_no_session() {
        let (err, _) = typed(Trigger::SignedOutMidRefresh).await;
        assert!(
            matches!(
                find(&err),
                Error::NoSession {
                    gone: SessionGone::SignedOutWhileRefreshing { .. },
                    ..
                }
            ),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn no_revocation_endpoint_is_a_revoke_error() {
        let (err, _) = typed(Trigger::TryRevokeNoEndpoint).await;
        assert!(
            matches!(find(&err), Error::Revoke(RevokeError::NoEndpoint)),
            "{err:#}"
        );
    }

    /// **Context a caller adds does not hide the variant**, and changes no
    /// text: `{err:#}` is the context, then exactly the message before.
    #[tokio::test]
    async fn a_variant_is_found_under_a_callers_context() {
        let (err, rendered) = typed(Trigger::ForeignBrowser).await;
        let wrapped = err.context("completing the login");
        assert_eq!(
            format!("{wrapped:#}"),
            format!("completing the login: {rendered}")
        );
        assert!(matches!(
            Error::find(&wrapped),
            Some(Error::Callback(CallbackError::BindingMismatch))
        ));
    }

    /// **An error with no decision behind it is not a calamus::Error**, and
    /// converting one keeps it whole as `Other`; converting a typed one
    /// recovers its variant.
    #[tokio::test]
    async fn an_untyped_error_is_other_with_its_text_intact() {
        let (err, rendered) = typed(Trigger::JwsTwoSegments).await;
        assert!(Error::find(&err).is_none(), "{err:#}");
        let converted = Error::from(err);
        assert!(matches!(converted, Error::Other(_)));
        assert_eq!(format!("{converted}"), rendered);

        let (err, _) = typed(Trigger::UnknownState).await;
        assert!(matches!(
            Error::from(err),
            Error::Callback(CallbackError::NoPendingLogin)
        ));
    }
}
