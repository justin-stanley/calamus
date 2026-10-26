//! RFC 7009 token revocation — what "log out" actually means at the PDS.
//!
//! Without this, signing out only drops the local row: the refresh token stays
//! live at the authorization server until it expires on its own, so a stolen
//! copy of the database still yields a working session long after the user
//! believes they are out.
//!
//! Two halves:
//!
//! * **The request** (always built): [`try_revoke`], [`revoke_tokens`] and
//!   [`revoke_orphaned`], with [`token_to_revoke`] and [`revoke_params`]. The
//!   refresh path needs it: a refresh that finds its session signed out while
//!   it ran revokes the tokens it just obtained ([`crate::session`]).
//! * **The sign-out** (feature `revoke`): `sign_out` and `sign_out_with`, which
//!   revoke and then delete the local session over a
//!   [`crate::store::SessionStore`], bounded and race-safe.
//!
//! Ported from FeatherReader `src/oauth/revoke.rs`. Its operator tooling (the
//! fleet-wide revoke-all, its pre-flight and JWKS check) and the
//! discovery-driven sign-out stay in FeatherReader: they read its
//! configuration, and the JWKS check deliberately bypasses the SSRF guard.

use anyhow::Result;

use crate::client_auth::{self, AuthMethod};
use crate::dpop::Endpoint;
use crate::keys::SigningKey;
use crate::net::Fetcher;
use crate::request::{send_with_dpop_at, DpopBody, DpopRequest, Retry};
#[cfg(feature = "revoke")]
use crate::store::SessionStore;
use crate::store::{NonceStore, Session};

/// What happened at the authorization server. Never an `Err` at the call site:
/// the caller has already decided to sign the user out, and the question is only
/// whether the server was told too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revocation {
    /// The server accepted the revocation.
    Revoked,
    /// There was no session to revoke — logout is idempotent.
    NoSession,
    /// The attempt failed. The local row is gone regardless, except where
    /// `sign_out` says it is left: a row that kept rotating, or one at another
    /// authorization server than the endpoint's.
    Failed(String),
}

/// Which of a session's two tokens to present, and its `token_type_hint`.
///
/// **The refresh token, whenever there is one.** RFC 7009 §2.1: revoking a
/// refresh token SHOULD also invalidate every access token issued under the same
/// grant, so one call ends the whole thing. Revoking the access token alone
/// leaves the refresh token live, and a refresh token is precisely what turns a
/// stale database dump back into a working session.
///
/// The reference is split on this — `oauth-session.js` `signOut()` revokes the
/// access token while `session-getter.js` revokes `refresh_token ?? access_token`
/// — and this follows the stronger of the two.
pub fn token_to_revoke(session: &Session) -> (&str, &'static str) {
    if session.refresh_token.is_empty() {
        (&session.access_token, "access_token")
    } else {
        (&session.refresh_token, "refresh_token")
    }
}

/// The form body for a revocation request, client credentials included.
///
/// No `token_type_hint` is sent, matching the reference. It is optional in RFC
/// 7009, and a server that cannot find the token under the hinted type MUST
/// search the other — so the hint can only save the server a lookup, never
/// change the outcome.
pub fn revoke_params(
    method: AuthMethod,
    client_id: &str,
    assertion: Option<&str>,
    token: &str,
) -> Result<Vec<(&'static str, String)>> {
    let mut params = vec![("token", token.to_string())];
    params.extend(client_auth::credential_params(
        method, client_id, assertion,
    )?);
    Ok(params)
}

/// Longest a sign-out will wait on the authorization server.
///
/// Sign-out is a foreground action a user is watching. Revocation is
/// best-effort by design, so the local delete must not be held behind an
/// unbounded wait on a server that may be down.
pub const REVOKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The deadline a background revocation (not a user's sign-out) waits for.
pub const ORPHAN_REVOKE_DEADLINE: std::time::Duration = REVOKE_DEADLINE;

/// What a revocation needs beyond the session itself. Mirrors
/// [`crate::session::RefreshContext`]; `aud` is the issuer for both.
pub struct RevokeContext<'a> {
    /// From the authorization server's metadata. Absent when the server
    /// advertises none, which is itself a reason revocation cannot happen.
    pub revocation_endpoint: Option<&'a str>,
    /// This client's `client_id`.
    pub client_id: &'a str,
    /// How this client authenticates.
    pub auth_method: AuthMethod,
    /// The confidential client's signing key; unused by the dev client.
    pub client_key: Option<&'a SigningKey>,
    /// Longest to wait on the authorization server before giving up. Injectable
    /// so the deadline can be TESTED without a five-second test.
    pub deadline: std::time::Duration,
    /// The authorization server `revocation_endpoint` was discovered for. A
    /// session whose issuer is any other is refused before anything is sent
    /// ([`crate::discovery::same_issuer`]): another server answers 200 for a
    /// token it does not know, so the grant stays live while this reports it
    /// revoked, and its refresh token has been handed to that server.
    ///
    /// **Set it to the issuer you ran discovery FOR**, usually the `issuer` of
    /// your own earlier read of the session. It is not compared with itself:
    /// `sign_out` reads the row again (and again, if a refresh rotates it),
    /// and the row it ends up revoking can be a different grant at another
    /// authorization server (a re-login after a PDS migration). The check ties
    /// the endpoint to the grant actually being sent there; such a row is left
    /// for a sign-out that discovers its own issuer.
    pub issuer: &'a str,
}

/// Revoke a token set that has NO local row to delete — bounded by
/// `ctx.deadline`, best-effort, never touching any session store.
///
/// For tokens obtained for a session that was signed out while they were being
/// obtained: a refresh that finds its row deleted holds a live grant nobody
/// will ever use, and dropping it would leave it live at the PDS until expiry.
pub async fn revoke_orphaned(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    session: &Session,
    now: i64,
) -> Revocation {
    revoke_orphaned_at(fetcher, nonces, ctx, session, crate::Elapsing::from(now)).await
}

/// [`revoke_orphaned`] on the caller's clock.
pub(crate) async fn revoke_orphaned_at(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    session: &Session,
    clock: crate::Elapsing,
) -> Revocation {
    match tokio::time::timeout(
        ctx.deadline,
        revoke_tokens_at(fetcher, nonces, ctx, session, clock),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => Revocation::Failed(format!(
            "revocation did not finish within {:?}",
            ctx.deadline
        )),
    }
}

/// The revocation request, unbounded. Errors become [`Revocation::Failed`]
/// rather than propagating: every caller has already committed to signing out.
pub async fn revoke_tokens(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    session: &Session,
    now: i64,
) -> Revocation {
    revoke_tokens_at(fetcher, nonces, ctx, session, crate::Elapsing::from(now)).await
}

/// [`revoke_tokens`] on the caller's clock.
pub(crate) async fn revoke_tokens_at(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    session: &Session,
    clock: crate::Elapsing,
) -> Revocation {
    match try_revoke_at(fetcher, nonces, ctx, session, clock).await {
        Ok(()) => Revocation::Revoked,
        Err(err) => Revocation::Failed(format!("{err:#}")),
    }
}

/// POST [`token_to_revoke`] to the revocation endpoint, with this client's
/// credentials, proved with the session's own DPoP key. `Ok` on any 2xx.
///
/// The endpoint must come from discovery for the session's OWN issuer, and
/// `ctx.issuer` must say which issuer that was: a session from any other is
/// refused with nothing sent. `now` is the time at the call; the assertion and
/// the proof carry the time they are minted.
pub async fn try_revoke(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    session: &Session,
    now: i64,
) -> Result<()> {
    try_revoke_at(fetcher, nonces, ctx, session, crate::Elapsing::from(now)).await
}

/// [`try_revoke`] on the caller's clock: a nested call does not re-anchor it.
pub(crate) async fn try_revoke_at(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    session: &Session,
    clock: crate::Elapsing,
) -> Result<()> {
    // Before anything else: this sends the REFRESH TOKEN.
    crate::discovery::same_issuer(ctx.issuer, &session.issuer)?;
    let endpoint = ctx.revocation_endpoint.ok_or_else(|| {
        anyhow::anyhow!("the authorization server advertises no revocation endpoint")
    })?;

    let (token, _hint) = token_to_revoke(session);
    let assertion = match ctx.auth_method {
        AuthMethod::PrivateKeyJwt => {
            let key = ctx.client_key.ok_or_else(|| {
                anyhow::anyhow!("private_key_jwt requires the client signing key")
            })?;
            Some(client_auth::client_assertion(
                key,
                ctx.client_id,
                &session.issuer,
                clock.now(),
            )?)
        }
        AuthMethod::None => None,
    };
    let params = revoke_params(ctx.auth_method, ctx.client_id, assertion.as_deref(), token)?;
    let form: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();

    // The session's own DPoP key, as for every other call on this grant: the
    // reference routes revocation through the same `dpopFetch`.
    let key = SigningKey::from_jwk_json(&session.dpop_key_jwk, "session")?;
    let (outcome, _) = send_with_dpop_at(
        fetcher,
        nonces,
        &DpopRequest {
            endpoint: Endpoint::AuthorizationServer,
            url: endpoint,
            key: &key,
            access_token: None,
            body: DpopBody::Form(&form),
            retry: Retry::Allowed,
        },
        clock,
    )
    .await?;
    // Every response, not just failures: a 2xx here is the evidence that
    // revocation ran against a live server (FeatherReader #262).
    client_auth::log_evidence(
        "revoke",
        client_auth::evidence(&params),
        endpoint,
        outcome.status,
    );

    // RFC 7009 §2.2: a 200 also means "we did not recognise that token", which
    // is success for our purposes — the grant is not usable either way.
    if !(200..300).contains(&outcome.status) {
        anyhow::bail!("the revocation endpoint returned status {}", outcome.status);
    }
    Ok(())
}

/// Sign a subject out: tell the authorization server, then drop the local row.
///
/// **The local row goes regardless of what the server says.** The user asked to
/// be logged out; a server that is down, slow, or has already forgotten the
/// grant must not leave a usable session sitting in our store. The reference
/// encodes the same ordering as `try { revoke } finally { delStored }`, and the
/// failure it guards against is the worse one: reporting an error to the user
/// while their credentials stay live locally.
///
/// Revocation is attempted FIRST, because it needs the tokens the delete
/// destroys — but it is BOUNDED by `ctx.deadline`. The whole design already
/// treats a failed revocation as acceptable, so making the user wait out a dead
/// PDS's timeouts to reach a delete that happens regardless is the wrong trade.
/// Past the deadline the attempt is abandoned and the local session goes.
///
/// `ctx.revocation_endpoint` must be the one discovered for `ctx.issuer`. A row
/// read (or re-read after a change) that belongs to another issuer (a re-login
/// after a PDS migration) is a live grant this endpoint cannot end: its tokens
/// are NOT sent here, and the row is NOT deleted. Deleting it would drop a live
/// token unrevoked with no record left to retry from, which is the same reason
/// a row that keeps rotating is left in place. The outcome is
/// [`Revocation::Failed`], naming the issuer; a sign-out that discovers THAT
/// row's issuer can finish it. A caller that discovers the endpoint per session
/// (it is not stored on the session) uses [`sign_out_with`] and discovers
/// inside the attempt, for the row each attempt actually read.
#[cfg(feature = "revoke")]
pub async fn sign_out(
    store: &impl SessionStore,
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RevokeContext<'_>,
    sub: &str,
    now: i64,
) -> Revocation {
    // Each attempt revokes at ITS time: up to three of them, each bounded by
    // the deadline, so the last can start well after `now`.
    let clock = crate::Elapsing::from(now);
    sign_out_checked(
        store,
        sub,
        ctx.deadline,
        |session| {
            crate::discovery::same_issuer(ctx.issuer, &session.issuer)
                .err()
                .map(|err| {
                    Revocation::Failed(format!(
                        "{err:#}; the session was left in place for a sign-out at its own \
                         authorization server"
                    ))
                })
        },
        |session| async move { revoke_tokens_at(fetcher, nonces, ctx, &session, clock).await },
    )
    .await
}

/// [`sign_out`] with the revocation injected: `revoke` is called with each
/// session read, and its outcome reported.
///
/// The single implementation of the sign-out contract: read the row with its
/// version, revoke under `deadline`, then delete the row **only if it is still
/// the one that was revoked**. A row rewritten in between (a refresh rotated
/// it) is read again and its new tokens revoked, up to three attempts; one that
/// keeps changing is left in place, newest tokens on record, and reported as
/// [`Revocation::Failed`]. A row that cannot be read is deleted anyway.
#[cfg(feature = "revoke")]
pub async fn sign_out_with<S, F, Fut>(
    store: &S,
    sub: &str,
    deadline: std::time::Duration,
    revoke: F,
) -> Revocation
where
    S: SessionStore,
    F: FnMut(Session) -> Fut,
    Fut: std::future::Future<Output = Revocation>,
{
    sign_out_checked(store, sub, deadline, |_| None, revoke).await
}

/// [`sign_out_with`], with `refuse` asked about each row read before anything
/// is sent for it: `Some(outcome)` ends the sign-out with that outcome, the
/// row neither revoked nor deleted.
#[cfg(feature = "revoke")]
async fn sign_out_checked<S, R, F, Fut>(
    store: &S,
    sub: &str,
    deadline: std::time::Duration,
    refuse: R,
    mut revoke: F,
) -> Revocation
where
    S: SessionStore,
    R: Fn(&Session) -> Option<Revocation>,
    F: FnMut(Session) -> Fut,
    Fut: std::future::Future<Output = Revocation>,
{
    // The outcome of the last attempt whose row then changed under it.
    let mut previous: Option<Revocation> = None;
    for _ in 0..MAX_SIGN_OUT_ATTEMPTS {
        let (session, version) = match store.get_versioned(sub).await {
            Ok(Some(read)) => read,
            // Gone — first time round, there was nothing to sign out; after
            // a `Changed`, someone else (a concurrent logout) deleted it
            // once we had revoked what we read, so report that revocation.
            Ok(None) => return previous.unwrap_or(Revocation::NoSession),
            Err(err) => {
                // Still delete: an unreadable row is exactly the state a
                // sign-out should clear, and leaving it wedges every later
                // request. No refresh can rotate a row nothing can read.
                let _ = store.delete(sub).await;
                return Revocation::Failed(format!("reading the session: {err:#}"));
            }
        };
        if let Some(refused) = refuse(&session) {
            return refused;
        }

        match bounded_then_delete(store, sub, &version, deadline, revoke(session)).await {
            Attempt::Done(outcome) => return outcome,
            // Rotated (or removed) while we revoked: read again and revoke the
            // tokens that are actually on record now.
            Attempt::Changed(outcome) => previous = Some(outcome),
        }
    }
    // Still rotating. Leave the newest tokens IN PLACE — deleting them would
    // drop a live token unrevoked with no record left to retry from — and say
    // so, so a later sweep (or the user's next sign-out) can finish it.
    Revocation::Failed(format!(
        "the session kept changing while it was being signed out ({MAX_SIGN_OUT_ATTEMPTS} \
         attempts, each overtaken by a refresh); its newest tokens were left in place"
    ))
}

/// How many times a sign-out re-reads and re-revokes a session that a
/// concurrent refresh keeps rotating, before giving up and leaving the newest
/// tokens on record.
#[cfg(feature = "revoke")]
const MAX_SIGN_OUT_ATTEMPTS: usize = 3;

/// What one bounded attempt ended in.
#[cfg(feature = "revoke")]
#[derive(Debug)]
enum Attempt {
    /// The row that was revoked has been deleted (or the delete failed, which
    /// is reported in the outcome). Final.
    Done(Revocation),
    /// The row was rewritten or removed after it was read, so the revoked token
    /// was not the one on record. Nothing was deleted.
    Changed(Revocation),
}

/// Run `attempt` under `deadline`, then delete the local session — **whatever
/// the server said**, including when the deadline expired — provided the row
/// still holds the `version` that was revoked.
///
/// Separated out from [`sign_out_with`] so the bound can be tested against a
/// future that never resolves, rather than against a network address that may
/// be refused instantly in one environment and hang in another.
///
/// **Compare-and-delete, not delete.** A refresh can rotate the row between
/// the read and here (a refresh holds an in-process lock that neither another
/// process's revoke-all nor a racing logout holds). An unconditional delete
/// then removed the ROTATED token, which was never revoked; the caller now
/// re-reads and revokes that one instead.
#[cfg(feature = "revoke")]
async fn bounded_then_delete<S, F>(
    store: &S,
    sub: &str,
    version: &S::Version,
    deadline: std::time::Duration,
    attempt: F,
) -> Attempt
where
    S: SessionStore,
    F: std::future::Future<Output = Revocation>,
{
    let outcome = match tokio::time::timeout(deadline, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => Revocation::Failed(format!(
            "revocation did not finish within {deadline:?}; signing out locally anyway"
        )),
    };

    // Unconditional on the OUTCOME — the user asked to be logged out — but
    // conditional on the row being the one whose tokens were just revoked.
    match store.delete_if_unchanged(sub, version).await {
        Ok(true) => Attempt::Done(outcome),
        Ok(false) => Attempt::Changed(outcome),
        Err(err) => Attempt::Done(Revocation::Failed(format!(
            "deleting the local session: {err:#}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_auth::AuthMethod;
    use crate::keys::SigningKey;
    use crate::net::Fetcher;
    use crate::store::memory::MemoryNonces;
    use crate::store::Session;
    use crate::testing::{spawn_tls, test_host_override, TestResponse};

    fn session(access: &str, refresh: &str) -> Session {
        Session {
            sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            issuer: "https://pds.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: r#"{"kty":"EC"}"#.into(),
            access_token: access.into(),
            refresh_token: refresh.into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto".into(),
            expires_at: Some(1_700_000_000),
        }
    }

    /// **The refresh token is the one that matters.**
    ///
    /// Revoking the access token alone ends a session that was going to expire
    /// within the hour anyway, and leaves live the one credential that can mint
    /// replacements indefinitely. RFC 7009 §2.1 makes revoking the refresh token
    /// cover both.
    #[test]
    fn the_refresh_token_is_preferred_over_the_access_token() {
        let session = session("access-abc", "refresh-xyz");
        let (token, hint) = token_to_revoke(&session);
        assert_eq!(
            token, "refresh-xyz",
            "revoked the access token, leaving the refresh token live"
        );
        assert_eq!(hint, "refresh_token");
    }

    /// A token response may omit `refresh_token` entirely. Then the access token
    /// is all there is, and revoking it is better than revoking nothing.
    #[test]
    fn an_absent_refresh_token_falls_back_to_the_access_token() {
        let session = session("access-abc", "");
        let (token, hint) = token_to_revoke(&session);
        assert_eq!(token, "access-abc");
        assert_eq!(hint, "access_token");
    }

    /// A public client sends `client_id` and no assertion — the same rule the
    /// rest of the client-auth surface follows.
    #[test]
    fn a_public_client_sends_the_token_and_its_client_id() {
        let params = revoke_params(AuthMethod::None, "http://localhost", None, "refresh-xyz")
            .expect("a public client needs no assertion");
        assert!(params.contains(&("token", "refresh-xyz".to_string())));
        assert!(params.contains(&("client_id", "http://localhost".to_string())));
        assert!(
            !params
                .iter()
                .any(|(k, _)| k.starts_with("client_assertion")),
            "a public client must not send an assertion it never registered: {params:?}"
        );
    }

    /// A confidential client carries its assertion, so revocation authenticates
    /// the same way PAR and token do.
    #[test]
    fn a_confidential_client_carries_its_assertion() {
        let params = revoke_params(
            AuthMethod::PrivateKeyJwt,
            "https://feather-reader.com/oauth/client-metadata.json",
            Some("the.assertion.jwt"),
            "refresh-xyz",
        )
        .expect("an assertion was supplied");
        assert!(params.contains(&("client_assertion", "the.assertion.jwt".to_string())));
    }

    /// Revocation must not authenticate as an unauthenticated request when the
    /// assertion is missing — that would silently fail at the server and report
    /// success locally.
    #[test]
    fn a_confidential_client_without_an_assertion_is_an_error() {
        let err = revoke_params(AuthMethod::PrivateKeyJwt, "https://client", None, "tok")
            .expect_err("must not send an unauthenticated revocation");
        assert!(format!("{err:#}").contains("requires a client assertion"));
    }

    // ── the request itself, over real TLS ───────────────────────────────────

    const NOW: i64 = 1_700_000_000;

    /// An authorization server over real TLS answering `/revoke` with `reply`;
    /// the Fetcher that reaches it, the endpoint, and the request log.
    async fn revocation_server(
        reply: TestResponse,
    ) -> (
        Fetcher,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        revocation_server_replies(vec![reply]).await
    }

    /// [`revocation_server`] with successive replies (the last repeats).
    async fn revocation_server_replies(
        replies: Vec<TestResponse>,
    ) -> (
        Fetcher,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let (addr, log) = spawn_tls(move |_| {
            let mut r = std::collections::HashMap::new();
            r.insert("/revoke".to_string(), replies);
            r
        })
        .await;
        let fetcher = Fetcher::default();
        test_host_override(&fetcher, "as-e2e.test", addr);
        (
            fetcher,
            format!("https://as-e2e.test:{}/revoke", addr.port()),
            log,
        )
    }

    fn public_ctx(endpoint: &str) -> RevokeContext<'_> {
        RevokeContext {
            revocation_endpoint: Some(endpoint),
            client_id: "http://localhost",
            auth_method: AuthMethod::None,
            client_key: None,
            deadline: std::time::Duration::from_secs(5),
            issuer: ISSUER,
        }
    }

    /// The issuer [`session`] belongs to.
    const ISSUER: &str = "https://pds.example.com";

    fn revoke_requests(log: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST /revoke"))
            .cloned()
            .collect()
    }

    fn jwt_part(jwt: &str, idx: usize) -> serde_json::Value {
        use base64::Engine as _;
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwt.split('.').nth(idx).expect("malformed JWT"))
                .expect("not base64url"),
        )
        .expect("not JSON")
    }

    fn form_param(raw: &str, name: &str) -> Option<String> {
        let (_, body) = raw.split_once("\r\n\r\n").expect("no body");
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    fn keyed_session() -> (SigningKey, Session) {
        let key = SigningKey::generate("session");
        let session = Session {
            dpop_key_jwk: key.to_jwk_json().unwrap(),
            ..session("access-abc", "refresh-xyz")
        };
        (key, session)
    }

    /// **A revocation answers one nonce challenge, as an authorization-server
    /// request, and proves without `ath`.** Two requests, the second with the
    /// challenge's nonce, no access token on either.
    #[tokio::test]
    async fn a_revocation_answers_one_nonce_challenge_and_proves_without_ath() {
        let (fetcher, endpoint, log) = revocation_server_replies(vec![
            TestResponse::json(400, r#"{"error":"use_dpop_nonce"}"#)
                .with_header("DPoP-Nonce", "revoke-nonce"),
            TestResponse::json(200, "{}"),
        ])
        .await;
        let (_, session) = keyed_session();

        let outcome = revoke_tokens(
            &fetcher,
            &MemoryNonces::new(),
            &public_ctx(&endpoint),
            &session,
            NOW,
        )
        .await;
        assert_eq!(outcome, Revocation::Revoked);

        let reqs = revoke_requests(&log);
        assert_eq!(reqs.len(), 2, "{reqs:#?}");
        let claims: Vec<_> = reqs.iter().map(|r| jwt_part(&dpop_proof(r), 1)).collect();
        assert!(claims[0].get("nonce").is_none());
        assert_eq!(claims[1]["nonce"], "revoke-nonce");
        for (req, claims) in reqs.iter().zip(&claims) {
            assert!(
                claims.get("ath").is_none(),
                "a revocation proof carried ath: {claims}"
            );
            assert!(
                !req.to_ascii_lowercase().contains("\nauthorization:"),
                "an access token was sent to the revocation endpoint: {req}"
            );
        }
    }

    /// **A confidential client's revocation assertion is for the session's
    /// ISSUER**, not for the revocation endpoint's URL.
    #[tokio::test]
    async fn a_private_key_jwt_revocation_asserts_for_the_sessions_issuer() {
        let (fetcher, endpoint, log) = revocation_server(TestResponse::json(200, "{}")).await;
        let (_, session) = keyed_session();
        let client_key = SigningKey::generate("client-1");
        let client_id = "https://client.example/oauth-client-metadata.json";
        let ctx = RevokeContext {
            client_id,
            auth_method: AuthMethod::PrivateKeyJwt,
            client_key: Some(&client_key),
            ..public_ctx(&endpoint)
        };

        let outcome = revoke_tokens(&fetcher, &MemoryNonces::new(), &ctx, &session, NOW).await;
        assert_eq!(outcome, Revocation::Revoked);

        let reqs = revoke_requests(&log);
        let assertion = form_param(&reqs[0], "client_assertion").expect("no client_assertion");
        crate::jwt::verify(&client_key, &assertion).expect("not signed by the client key");
        let claims = jwt_part(&assertion, 1);
        assert_eq!(claims["aud"], ISSUER, "{claims}");
        assert_eq!(claims["iss"], client_id);
    }

    /// **A revocation refuses a session whose issuer is not the one the
    /// endpoint was discovered for.** Another authorization server answers 200
    /// for a token it does not know: reported revoked, grant live, and the
    /// refresh token handed to the wrong server. Nothing is sent.
    #[tokio::test]
    async fn a_revocation_refuses_a_session_from_another_issuer() {
        let (fetcher, endpoint, log) = revocation_server(TestResponse::json(200, "{}")).await;
        let (_, session) = keyed_session();
        let ctx = RevokeContext {
            issuer: "https://other-as.example.com",
            ..public_ctx(&endpoint)
        };

        let outcome = revoke_tokens(&fetcher, &MemoryNonces::new(), &ctx, &session, NOW).await;
        match &outcome {
            Revocation::Failed(reason) => {
                assert!(
                    reason.contains("different authorization server"),
                    "{reason}"
                )
            }
            other => panic!("another issuer's endpoint must be refused: {other:?}"),
        }
        assert!(log.lock().unwrap().is_empty(), "{:#?}", log.lock().unwrap());
    }

    /// **RFC 7009 §2.2: a 200 also means "that token was not recognised".** The
    /// server answers 200 for an invalid or unknown token, and that is success
    /// for a revocation: the grant is not usable either way. Treating the error
    /// body as a failure would report a sign-out as failed when the token is in
    /// fact dead.
    #[tokio::test]
    async fn a_200_for_an_unknown_token_is_revoked() {
        let (fetcher, endpoint, log) =
            revocation_server(TestResponse::json(200, r#"{"error":"unknown"}"#)).await;
        let session = Session {
            dpop_key_jwk: SigningKey::generate("session").to_jwk_json().unwrap(),
            ..session("access-abc", "refresh-xyz")
        };

        let outcome = revoke_tokens(
            &fetcher,
            &MemoryNonces::new(),
            &public_ctx(&endpoint),
            &session,
            NOW,
        )
        .await;

        assert_eq!(outcome, Revocation::Revoked);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with("POST /revoke"))
                .count(),
            1,
            "the revocation never reached the server"
        );
    }

    /// The `DPoP` header of one recorded request.
    fn dpop_proof(raw: &str) -> String {
        raw.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("dpop:"))
            .expect("no DPoP header on the request")[5..]
            .trim()
            .to_string()
    }

    /// **The revocation presents the REFRESH token, proved with the SESSION's
    /// DPoP key.** The grant is DPoP-bound: the server ties every token of it to
    /// that key, so a revocation proved with any other key (a fresh one, the
    /// client's signing key) is a request about a token the prover does not
    /// hold. The reference routes revocation through the same `dpopFetch` as
    /// every other call on the grant.
    #[tokio::test]
    async fn revocation_sends_the_refresh_token_under_the_sessions_dpop_key() {
        let (fetcher, endpoint, log) = revocation_server(TestResponse::json(200, "{}")).await;
        let key = SigningKey::generate("session");
        let session = Session {
            dpop_key_jwk: key.to_jwk_json().unwrap(),
            ..session("access-abc", "refresh-xyz")
        };

        let outcome = revoke_tokens(
            &fetcher,
            &MemoryNonces::new(),
            &public_ctx(&endpoint),
            &session,
            NOW,
        )
        .await;
        assert_eq!(outcome, Revocation::Revoked);

        let requests = log.lock().unwrap().clone();
        let revoke = requests
            .iter()
            .find(|r| r.starts_with("POST /revoke"))
            .expect("no revocation request");
        let (_, body) = revoke.split_once("\r\n\r\n").expect("no body");
        let form: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert!(
            form.contains(&("token".into(), "refresh-xyz".into())),
            "the refresh token was not the one presented: {form:?}"
        );
        assert!(
            !body.contains("access-abc"),
            "the access token was sent: {body}"
        );

        use base64::Engine as _;
        let proof = dpop_proof(revoke);
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(proof.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["typ"], "dpop+jwt", "{header}");
        let presented = SigningKey::public_thumbprint_of(&header["jwk"].to_string()).unwrap();
        assert_eq!(
            presented,
            key.thumbprint().unwrap(),
            "the revocation was proved with a key other than the session's"
        );
        crate::jwt::verify(&key, &proof).expect("the proof is not signed by the session key");
    }

    // ── the sign-out invariant (feature `revoke`) ────────────────────────────

    #[cfg(feature = "revoke")]
    mod sign_out {
        use super::super::*;
        use super::session;
        use crate::client_auth::AuthMethod;
        use crate::keys::SigningKey;
        use crate::net::Fetcher;
        use crate::store::memory::{MemoryNonces, MemorySessions};
        use crate::store::{Session, SessionStore};

        const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        const NOW: i64 = 1_700_000_000;

        /// A real session row, with a real DPoP key so the request gets as far as
        /// the network rather than failing on key parsing.
        async fn stored(store: &MemorySessions) -> Session {
            let key = SigningKey::generate("session");
            let session = Session {
                dpop_key_jwk: key.to_jwk_json().unwrap(),
                ..session("access-abc", "refresh-xyz")
            };
            store.put(&session).await.unwrap();
            session
        }

        /// A short deadline: the property under test is that the wait is BOUNDED,
        /// and proving that with the production five seconds would make the whole
        /// suite ten times slower for one assertion.
        const TEST_DEADLINE: std::time::Duration = std::time::Duration::from_millis(250);

        fn ctx(endpoint: Option<&str>) -> RevokeContext<'_> {
            RevokeContext {
                revocation_endpoint: endpoint,
                client_id: "http://localhost",
                auth_method: AuthMethod::None,
                client_key: None,
                deadline: TEST_DEADLINE,
                issuer: "https://pds.example.com",
            }
        }

        /// **The session must be gone even when the server could not be told.**
        ///
        /// This is the whole reason the delete is unconditional. If revocation
        /// failing aborted the sign-out, then a PDS that is down — or simply slow —
        /// would leave a fully usable session in the database of a user who has been
        /// shown a "signed out" page. The loopback endpoint here is refused by the
        /// SSRF guard, which is a revocation failure that needs no network.
        #[tokio::test]
        async fn signing_out_deletes_the_local_session_even_when_revocation_fails() {
            let store = MemorySessions::new();
            stored(&store).await;

            let outcome = sign_out(
                &store,
                &Fetcher::default(),
                &MemoryNonces::new(),
                &ctx(Some("http://127.0.0.1/oauth/revoke")),
                DID,
                NOW,
            )
            .await;

            match &outcome {
                Revocation::Failed(reason) => assert!(
                    reason.contains("forbidden (internal) address"),
                    "failed BEFORE reaching the network, so this proves nothing about a \
                     revocation failure: {reason}"
                ),
                other => panic!("the loopback endpoint must not report success: {other:?}"),
            }
            assert!(
                store.get(DID).await.unwrap().is_none(),
                "THE SESSION SURVIVED A FAILED REVOCATION — a signed-out user still has live credentials"
            );
        }

        /// A server with no `revocation_endpoint` cannot be told, but the user is
        /// still signed out locally.
        #[tokio::test]
        async fn a_server_without_a_revocation_endpoint_still_signs_out_locally() {
            let store = MemorySessions::new();
            stored(&store).await;

            let outcome = sign_out(
                &store,
                &Fetcher::default(),
                &MemoryNonces::new(),
                &ctx(None),
                DID,
                NOW,
            )
            .await;

            match &outcome {
                Revocation::Failed(reason) => assert!(
                    reason.contains("no revocation endpoint"),
                    "failed for the wrong reason: {reason}"
                ),
                other => panic!("expected a failure, got {other:?}"),
            }
            assert!(store.get(DID).await.unwrap().is_none());
        }

        /// **A dead authorization server must not hold a sign-out open — and the
        /// bound must cover DISCOVERY, not just the revocation request.**
        ///
        /// Bounding only the request left the real wait unbounded: discovery makes
        /// two guarded fetches with a 30-second timeout each, so an unreachable PDS
        /// held the sign-out for a minute before the deadline began. The earlier
        /// version of this test missed that by exercising `sign_out` rather than the
        /// function production calls, and it reached the network to do it — so where
        /// outbound was refused it passed instantly, proving nothing.
        ///
        /// Exercised against a future that never resolves, with a short deadline:
        /// deterministic, no network, and it proves the bound rather than observing
        /// how long a particular host happens to take to refuse a connection.
        #[tokio::test]
        async fn a_hanging_attempt_does_not_hold_the_sign_out_open() {
            let store = MemorySessions::new();
            stored(&store).await;

            let (_, version) = store.get_versioned(DID).await.unwrap().unwrap();
            let started = std::time::Instant::now();
            let attempt = bounded_then_delete(
                &store,
                DID,
                &version,
                std::time::Duration::from_millis(50),
                std::future::pending::<Revocation>(),
            )
            .await;
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "the bound did not fire"
            );

            let Attempt::Done(outcome) = attempt else {
                panic!("the unchanged row was not deleted: {attempt:?}");
            };
            match &outcome {
                Revocation::Failed(reason) => assert!(
                    reason.contains("did not finish within"),
                    "failed for the wrong reason: {reason}"
                ),
                other => panic!("a never-resolving attempt must time out, got {other:?}"),
            }
            assert!(
                store.get(DID).await.unwrap().is_none(),
                "the session survived a timed-out revocation"
            );
        }

        /// A [`MemorySessions`] whose reads fail, as a database row that no
        /// longer decrypts does (FeatherReader: a row whose bound context was
        /// altered). Deletes still work.
        struct Unreadable(MemorySessions);

        impl SessionStore for Unreadable {
            type Version = <MemorySessions as SessionStore>::Version;

            async fn get(&self, _sub: &str) -> anyhow::Result<Option<Session>> {
                anyhow::bail!(
                    "decrypting the stored refresh token (or its bound context was altered)"
                )
            }
            async fn get_versioned(
                &self,
                _sub: &str,
            ) -> anyhow::Result<Option<(Session, Self::Version)>> {
                anyhow::bail!(
                    "decrypting the stored refresh token (or its bound context was altered)"
                )
            }
            async fn put(&self, session: &Session) -> anyhow::Result<()> {
                self.0.put(session).await
            }
            async fn update_if_unchanged(
                &self,
                session: &Session,
                version: &Self::Version,
            ) -> anyhow::Result<bool> {
                self.0.update_if_unchanged(session, version).await
            }
            async fn delete(&self, sub: &str) -> anyhow::Result<bool> {
                self.0.delete(sub).await
            }
            async fn delete_if_unchanged(
                &self,
                sub: &str,
                version: &Self::Version,
            ) -> anyhow::Result<bool> {
                self.0.delete_if_unchanged(sub, version).await
            }
        }

        /// **An UNREADABLE session row is still deleted.**
        ///
        /// A row whose bound context was altered no longer decrypts, so
        /// `get_session` returns an error. Returning early without deleting left
        /// that row in place — and because every repo call reads it, the account
        /// then failed on every page load with no way out but a sign-out that had
        /// just refused to clear it.
        #[tokio::test]
        async fn an_unreadable_session_is_still_signed_out() {
            let store = Unreadable(MemorySessions::new());
            stored(&store.0).await;
            assert!(
                store.get(DID).await.is_err(),
                "precondition: the row must be unreadable"
            );

            let outcome = sign_out(
                &store,
                &Fetcher::default(),
                &MemoryNonces::new(),
                &ctx(Some("https://pds.example.com/oauth/revoke")),
                DID,
                NOW,
            )
            .await;
            assert!(matches!(outcome, Revocation::Failed(_)), "got {outcome:?}");

            assert!(
                store.0.get(DID).await.unwrap().is_none(),
                "an unreadable row survived a sign-out, so the account stays wedged"
            );
        }

        /// Logging out twice is not an error. The second call has nothing to revoke
        /// and says so, rather than reporting a failure the caller would log.
        #[tokio::test]
        async fn signing_out_without_a_session_is_idempotent() {
            let store = MemorySessions::new();
            let outcome = sign_out(
                &store,
                &Fetcher::default(),
                &MemoryNonces::new(),
                &ctx(Some("https://pds.example.com/oauth/revoke")),
                DID,
                NOW,
            )
            .await;
            assert_eq!(outcome, Revocation::NoSession);
        }

        // ── a refresh racing the sign-out ────────────────────────────────────

        /// Store a session with refresh token `refresh` — what the live app's
        /// refresh does, from its own process.
        async fn rotate_to(store: &MemorySessions, refresh: &str) {
            let key = SigningKey::generate("session");
            let session = Session {
                dpop_key_jwk: key.to_jwk_json().unwrap(),
                ..session("access-rotated", refresh)
            };
            store.put(&session).await.unwrap();
        }

        type Seen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

        /// **A refresh that rotates the row mid-sign-out gets ITS token revoked
        /// too — and the new token's row is never deleted unrevoked.**
        ///
        /// The live app refreshes under an in-process lock the operator's
        /// revoke-all (a separate process) cannot take. The sign-out read R1; the
        /// app rotated to R2; the PDS answers 200 for the already-rotated R1; and
        /// an unconditional delete then removed the row holding R2 — reported as
        /// revoked, never revoked, and gone from the record the post-stop sweep
        /// reads. The same interleaving reaches `/logout` against a request's
        /// background refresh, which takes that lock while `/logout` does not.
        #[tokio::test]
        async fn a_session_rotated_mid_sign_out_has_the_new_token_revoked_too() {
            let store = MemorySessions::new();
            stored(&store).await;
            let seen: Seen = Default::default();

            let outcome = sign_out_with(&store, DID, TEST_DEADLINE, |s| {
                let (store, seen) = (&store, seen.clone());
                async move {
                    let first = {
                        let mut v = seen.lock().unwrap();
                        v.push(s.refresh_token.clone());
                        v.len() == 1
                    };
                    if first {
                        // The app's refresh lands between our read and our delete.
                        rotate_to(store, "refresh-R2").await;
                    }
                    Revocation::Revoked
                }
            })
            .await;

            assert_eq!(
                *seen.lock().unwrap(),
                vec!["refresh-xyz".to_string(), "refresh-R2".to_string()],
                "the rotated token was never presented for revocation"
            );
            assert_eq!(outcome, Revocation::Revoked);
            assert!(
                store.get(DID).await.unwrap().is_none(),
                "the session survived a sign-out that revoked every version of it"
            );
        }

        /// A row that keeps rotating is given up on after a bounded number of
        /// attempts — reported as a failure, and the LATEST token left on record
        /// (so a later pass can revoke it) rather than deleted unrevoked.
        #[tokio::test]
        async fn a_session_that_keeps_rotating_is_reported_and_left_in_place() {
            let store = MemorySessions::new();
            stored(&store).await;
            let seen: Seen = Default::default();

            let outcome = sign_out_with(&store, DID, TEST_DEADLINE, |s| {
                let (store, seen) = (&store, seen.clone());
                async move {
                    let n = {
                        let mut v = seen.lock().unwrap();
                        v.push(s.refresh_token.clone());
                        v.len()
                    };
                    rotate_to(store, &format!("refresh-R{}", n + 1)).await;
                    Revocation::Revoked
                }
            })
            .await;

            let attempts = seen.lock().unwrap().len();
            assert_eq!(attempts, 3, "the retries were not bounded at 3");
            match &outcome {
                Revocation::Failed(reason) => assert!(
                    reason.contains("kept changing"),
                    "failed for the wrong reason: {reason}"
                ),
                other => panic!("a still-rotating session must not report success: {other:?}"),
            }
            let left = store
                .get(DID)
                .await
                .unwrap()
                .expect("the newest token was deleted unrevoked");
            assert_eq!(left.refresh_token, "refresh-R4");
        }

        /// A row that disappears mid-sign-out (a concurrent `/logout`) is not an
        /// error and not retried: the token that was read has been revoked, and
        /// there is nothing left to delete.
        #[tokio::test]
        async fn a_session_deleted_mid_sign_out_reports_the_revocation() {
            let store = MemorySessions::new();
            stored(&store).await;
            let seen: Seen = Default::default();

            let outcome = sign_out_with(&store, DID, TEST_DEADLINE, |s| {
                let (store, seen) = (&store, seen.clone());
                async move {
                    seen.lock().unwrap().push(s.refresh_token.clone());
                    store.delete(DID).await.unwrap();
                    Revocation::Revoked
                }
            })
            .await;
            assert_eq!(outcome, Revocation::Revoked);
            assert_eq!(seen.lock().unwrap().len(), 1, "retried a row that was gone");
        }

        /// A [`MemorySessions`] in which `relogin` replaces the row during the
        /// first revocation (just before its compare-and-delete): a re-login,
        /// after a PDS migration, at ANOTHER authorization server.
        struct ReloginDuringRevoke {
            inner: MemorySessions,
            relogin: std::sync::Mutex<Option<Session>>,
        }

        impl SessionStore for ReloginDuringRevoke {
            type Version = <MemorySessions as SessionStore>::Version;

            async fn get(&self, sub: &str) -> anyhow::Result<Option<Session>> {
                self.inner.get(sub).await
            }
            async fn get_versioned(
                &self,
                sub: &str,
            ) -> anyhow::Result<Option<(Session, Self::Version)>> {
                self.inner.get_versioned(sub).await
            }
            async fn put(&self, session: &Session) -> anyhow::Result<()> {
                self.inner.put(session).await
            }
            async fn update_if_unchanged(
                &self,
                session: &Session,
                version: &Self::Version,
            ) -> anyhow::Result<bool> {
                self.inner.update_if_unchanged(session, version).await
            }
            async fn delete(&self, sub: &str) -> anyhow::Result<bool> {
                self.inner.delete(sub).await
            }
            async fn delete_if_unchanged(
                &self,
                sub: &str,
                version: &Self::Version,
            ) -> anyhow::Result<bool> {
                let relogin = self.relogin.lock().unwrap().take();
                if let Some(relogin) = relogin {
                    self.inner.put(&relogin).await?;
                }
                self.inner.delete_if_unchanged(sub, version).await
            }
        }

        /// **A sign-out never sends a re-read grant from ANOTHER issuer to the
        /// endpoint it was given.** The sign-out re-reads a row that changed
        /// under it, and the re-read can be a new grant at a different
        /// authorization server (a re-login after a PDS migration). Its refresh
        /// token must not go to the old server's endpoint, which would answer
        /// 200 for a token it does not know: reported revoked, grant live.
        #[tokio::test]
        async fn a_sign_out_does_not_send_a_re_login_at_another_issuer_to_the_old_endpoint() {
            let (fetcher, endpoint, log) =
                super::revocation_server(crate::testing::TestResponse::json(200, "{}")).await;
            let store = ReloginDuringRevoke {
                inner: MemorySessions::new(),
                relogin: std::sync::Mutex::new(None),
            };
            stored(&store.inner).await;
            *store.relogin.lock().unwrap() = Some(Session {
                issuer: "https://as-other.test".into(),
                dpop_key_jwk: SigningKey::generate("session").to_jwk_json().unwrap(),
                ..session("access-moved", "refresh-moved")
            });

            let outcome = sign_out(
                &store,
                &fetcher,
                &MemoryNonces::new(),
                &RevokeContext {
                    deadline: std::time::Duration::from_secs(5),
                    ..ctx(Some(&endpoint))
                },
                DID,
                NOW,
            )
            .await;

            let revokes = super::revoke_requests(&log);
            assert_eq!(revokes.len(), 1, "{revokes:#?}");
            assert!(revokes[0].contains("token=refresh-xyz"), "{}", revokes[0]);
            assert!(
                !revokes.iter().any(|r| r.contains("refresh-moved")),
                "the other issuer's refresh token reached the old endpoint: {revokes:#?}"
            );
            match &outcome {
                Revocation::Failed(reason) => {
                    assert!(
                        reason.contains("different authorization server"),
                        "{reason}"
                    )
                }
                other => panic!("the moved grant was not revoked, so not Revoked: {other:?}"),
            }
            // And the re-login is LEFT, not deleted unrevoked: its grant is
            // live at its own authorization server, and a sign-out that
            // discovers that server is the one that can end it.
            let left = store.inner.get(DID).await.unwrap();
            assert_eq!(
                left.as_ref().map(|s| s.refresh_token.as_str()),
                Some("refresh-moved"),
                "the other issuer's re-login was deleted without being revoked"
            );
        }

        /// A [`MemorySessions`] whose `get_versioned` advances tokio's clock
        /// by `by` after reading.
        struct SlowRead {
            inner: MemorySessions,
            by: std::time::Duration,
        }

        impl SessionStore for SlowRead {
            type Version = <MemorySessions as SessionStore>::Version;

            async fn get(&self, sub: &str) -> anyhow::Result<Option<Session>> {
                self.inner.get(sub).await
            }
            async fn get_versioned(
                &self,
                sub: &str,
            ) -> anyhow::Result<Option<(Session, Self::Version)>> {
                let read = self.inner.get_versioned(sub).await;
                crate::testing::slow::advance(self.by).await;
                read
            }
            async fn put(&self, session: &Session) -> anyhow::Result<()> {
                self.inner.put(session).await
            }
            async fn update_if_unchanged(
                &self,
                session: &Session,
                version: &Self::Version,
            ) -> anyhow::Result<bool> {
                self.inner.update_if_unchanged(session, version).await
            }
            async fn delete(&self, sub: &str) -> anyhow::Result<bool> {
                self.inner.delete(sub).await
            }
            async fn delete_if_unchanged(
                &self,
                sub: &str,
                version: &Self::Version,
            ) -> anyhow::Result<bool> {
                self.inner.delete_if_unchanged(sub, version).await
            }
        }

        /// **One clock from the sign-out to the proof.** 0.6 s reading the
        /// row and 0.6 s reading the nonce is 1.2 s; re-anchoring at each
        /// level (sign_out, try_revoke, send_with_dpop) at truncated seconds
        /// made the proof say 0 s.
        #[tokio::test]
        async fn a_sign_out_proof_counts_every_fraction_once() {
            let (fetcher, endpoint, log) =
                super::revocation_server(crate::testing::TestResponse::json(200, "{}")).await;
            let store = SlowRead {
                inner: MemorySessions::new(),
                by: std::time::Duration::from_millis(600),
            };
            stored(&store.inner).await;
            let nonces = crate::testing::slow::SlowNonces {
                on_get: std::time::Duration::from_millis(600),
                ..Default::default()
            };

            let outcome = sign_out(
                &store,
                &fetcher,
                &nonces,
                &RevokeContext {
                    deadline: std::time::Duration::from_secs(5),
                    ..ctx(Some(&endpoint))
                },
                DID,
                NOW,
            )
            .await;
            assert_eq!(outcome, Revocation::Revoked);
            let revokes = super::revoke_requests(&log);
            let proof = super::dpop_proof(&revokes[0]);
            let iat = super::jwt_part(&proof, 1)["iat"].as_i64().unwrap();
            assert!(
                (NOW + 1..NOW + 3).contains(&iat),
                "1.2 s after the entry, the proof carried iat NOW{:+}",
                iat - NOW
            );
        }

        /// The sign-out future is `Send` for any stores. Compile-time.
        #[test]
        fn the_sign_out_future_is_send() {
            fn assert_send<T: Send>(_: &T) {}
            fn generic<S: SessionStore, N: crate::store::NonceStore>(store: &S, nonces: &N) {
                let fetcher = Fetcher::default();
                let ctx = ctx(None);
                assert_send(&sign_out(store, &fetcher, nonces, &ctx, DID, NOW));
            }
            generic(&MemorySessions::new(), &MemoryNonces::new());
        }
    }
}
