//! Holding a session valid: refresh-on-read, rotation, and what a failure means.
//!
//! Three things here are easy to get wrong and all three present as *random*
//! logouts rather than as a bug:
//!
//! * **Refresh tokens rotate and are single-use.** The new one must be stored
//!   atomically with the new access token, and a response that omits it means
//!   keep the old one — not store an empty string.
//! * **Concurrent refreshes must be serialized.** Two readers of the same
//!   session both presenting the same single-use token means the second gets
//!   `invalid_grant`, and most authorization servers revoke the first one's
//!   freshly issued tokens along with it. A background job plus one user
//!   request is already enough concurrency.
//! * **Only `invalid_grant` invalidates.** Deleting on a network blip or a 5xx
//!   logs people out for a server hiccup; treating a dead grant as transient
//!   retries forever and never prompts a re-login.
//!
//! Ported from FeatherReader `src/oauth/session.rs`, over
//! [`SessionStore`] and [`NonceStore`] instead of SQLite, with the clock passed
//! in. [`same_issuer`] now lives in [`crate::discovery`] and is re-exported here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::client_auth::{self, AuthMethod};
use crate::dpop::Endpoint;
use crate::keys::SigningKey;
use crate::net::Fetcher;
use crate::request::{send_with_dpop, DpopBody, DpopRequest, Retry};
use crate::revoke::{self, Revocation, RevokeContext};
use crate::store::{NonceStore, Session, SessionStore};
use crate::token::{self, RefreshFailure, TokenResponse};

pub use crate::discovery::same_issuer;

/// Fold a refresh response into the stored session.
///
/// Pure, so the rotation rules are testable without a server — which matters,
/// because every one of them fails as a mysterious logout rather than as an
/// error anyone can trace.
pub fn apply_refresh(session: &Session, response: &TokenResponse, now: i64) -> Result<Session> {
    // A refresh must never be able to move a session to another account.
    if response.sub != session.sub {
        bail!(
            "refresh returned subject {:?}, expected {:?}; refusing to rebind the session",
            response.sub,
            session.sub
        );
    }

    Ok(Session {
        access_token: response.access_token.clone(),
        // Rotation is expected but not guaranteed. Storing an empty string when
        // the server omits it would destroy the session on the next refresh,
        // with nothing to indicate why.
        refresh_token: response
            .refresh_token
            .clone()
            .unwrap_or_else(|| session.refresh_token.clone()),
        token_type: response.token_type.clone(),
        // The GRANTED scope, which the server may have narrowed. Keeping the old
        // value would make later write failures unexplainable.
        granted_scope: response.granted_scope.clone(),
        expires_at: response.expires_in.map(|seconds| now + seconds),
        // Properties of the session, not of any one token response.
        sub: session.sub.clone(),
        issuer: session.issuer.clone(),
        aud: session.aud.clone(),
        dpop_key_jwk: session.dpop_key_jwk.clone(),
    })
}

/// Per-subject refresh locks.
///
/// Two concurrent refreshes of one session both present the same single-use
/// refresh token; the loser gets `invalid_grant`, and most authorization servers
/// revoke the winner's freshly issued tokens along with it. The symptom is
/// random, unreproducible logouts.
///
/// **In-process only.** A second process is not covered, which is why the
/// refresh path also re-reads the stored session on `invalid_grant` before
/// concluding the grant is dead, and writes only over the row it read.
#[derive(Debug, Default, Clone)]
pub struct RefreshLocks {
    locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl RefreshLocks {
    /// Acquire the lock for one subject. Unrelated subjects never contend.
    pub async fn lock(&self, sub: &str) -> OwnedMutexGuard<()> {
        let entry = {
            // Recover rather than panic: this gates every token refresh, so a
            // poisoned lock here would lock every user out until a restart.
            let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(locks.entry(sub.to_string()).or_default())
        };
        entry.lock_owned().await
    }
}

/// What a refresh needs beyond the session itself.
///
/// `token_endpoint` and `revocation_endpoint` must come from a discovery whose
/// issuer was checked against the session's own ([`same_issuer`]): this path
/// sends the REFRESH TOKEN.
pub struct RefreshContext<'a> {
    /// The authorization server's token endpoint.
    pub token_endpoint: &'a str,
    /// This client's `client_id`.
    pub client_id: &'a str,
    /// How this client authenticates.
    pub auth_method: AuthMethod,
    /// The confidential client's signing key. Required for `private_key_jwt`,
    /// unused by the localhost dev client.
    pub client_key: Option<&'a SigningKey>,
    /// From the same discovery as `token_endpoint`. Used only when a refresh
    /// finds its session was signed out while it ran: the tokens it just
    /// obtained belong to no one, and are revoked rather than left live.
    pub revocation_endpoint: Option<&'a str>,
}

/// Read a session, refreshing it first if it is close to expiry. `now` is Unix
/// seconds.
///
/// **Do not wrap this in a timeout.** Once the refresh request is in flight the
/// authorization server has consumed the single-use refresh token; abandoning
/// the future means the replacement is never stored and the session is dead.
/// The reference carries the same warning for the same reason.
pub async fn valid_session(
    store: &impl SessionStore,
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    locks: &RefreshLocks,
    sub: &str,
    ctx: &RefreshContext<'_>,
    now: i64,
) -> Result<Session> {
    let session = store
        .get(sub)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no session for {sub}"))?;
    if !token::is_stale(session.expires_at, now) {
        return Ok(session);
    }

    let _guard = locks.lock(sub).await;

    // Re-read AFTER acquiring the lock: whoever held it may have refreshed while
    // we waited, and presenting the token they just replaced would burn it.
    let (session, version) = store
        .get_versioned(sub)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session for {sub} disappeared while waiting to refresh"))?;
    if !token::is_stale(session.expires_at, now) {
        return Ok(session);
    }

    refresh_locked(store, fetcher, nonces, &session, &version, ctx, now).await
}

/// A refresh succeeded at the server, but the row it started from is no longer
/// on record. Two cases:
///
/// Either way the tokens this refresh just obtained are stored NOWHERE, and
/// are revoked (best-effort, bounded) rather than left live at the PDS:
///
/// * **Rewritten** by another writer: theirs is the session on record, so it
///   is returned and ours is not written over it. In practice that writer is
///   a RE-LOGIN — a new grant. It cannot be a concurrent refresh of the same
///   token: refresh tokens are single-use, and ours succeeded. So our tokens
///   belong to the old grant, which nothing references any more.
/// * **Gone**: it was signed out while we refreshed. We now hold a live token
///   set for a session that no longer exists, and the caller gets the same
///   "no session" error a signed-out user gets.
async fn lost_the_row(
    store: &impl SessionStore,
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    ctx: &RefreshContext<'_>,
    obtained: &Session,
    now: i64,
) -> Result<Session> {
    let current = store.get(&obtained.sub).await?;
    let outcome = revoke::revoke_orphaned(
        fetcher,
        nonces,
        &RevokeContext {
            revocation_endpoint: ctx.revocation_endpoint,
            client_id: ctx.client_id,
            auth_method: ctx.auth_method,
            client_key: ctx.client_key,
            deadline: revoke::ORPHAN_REVOKE_DEADLINE,
        },
        obtained,
        now,
    )
    .await;
    if let Revocation::Failed(reason) = &outcome {
        tracing::warn!(
            sub = %obtained.sub,
            %reason,
            "a session changed or was signed out during its refresh: the refresh's \
             unstored new tokens could not be revoked"
        );
    }
    if let Some(current) = current {
        return Ok(current);
    }
    bail!(
        "no session for {}: it was signed out while being refreshed (the new tokens were \
         not stored{})",
        obtained.sub,
        if outcome == Revocation::Revoked {
            ", and were revoked"
        } else {
            ""
        }
    )
}

/// The refresh itself. Called with the subject's lock held; `version` is the
/// stored form of `session` as read under that lock.
async fn refresh_locked<S: SessionStore>(
    store: &S,
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    session: &Session,
    version: &S::Version,
    ctx: &RefreshContext<'_>,
    now: i64,
) -> Result<Session> {
    let key = SigningKey::from_jwk_json(&session.dpop_key_jwk, "session-dpop")?;

    let assertion = match ctx.auth_method {
        AuthMethod::PrivateKeyJwt => {
            let client_key = ctx
                .client_key
                .ok_or_else(|| anyhow::anyhow!("private_key_jwt refresh needs the client key"))?;
            Some(client_auth::client_assertion(
                client_key,
                ctx.client_id,
                &session.issuer,
                now,
            )?)
        }
        AuthMethod::None => None,
    };

    let mut params = token::refresh_request_params(&session.refresh_token);
    params.extend(client_auth::credential_params(
        ctx.auth_method,
        ctx.client_id,
        assertion.as_deref(),
    )?);
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let outcome = send_with_dpop(
        fetcher,
        nonces,
        &DpopRequest {
            endpoint: Endpoint::AuthorizationServer,
            url: ctx.token_endpoint,
            key: &key,
            access_token: None,
            body: DpopBody::Form(&borrowed),
            // A refresh is safe to repeat on a nonce challenge: unlike the code
            // exchange, a rejected attempt consumes nothing.
            retry: Retry::Allowed,
        },
        now,
    )
    .await?;
    client_auth::log_evidence(
        "refresh",
        client_auth::evidence(&params),
        ctx.token_endpoint,
        outcome.status,
    );

    if outcome.is_success() {
        let response = token::parse_token_response(&outcome.json()?)?;
        let updated = apply_refresh(session, &response, now)?;
        // **Conditional on the row we started from — never an upsert.** The
        // lock above is in-process; a sign-out (a logout, account deletion, an
        // operator's revoke-all in another process) does not take it. An
        // upsert landing after such a sign-out's delete RESURRECTED the
        // session with these fresh tokens, after it had been reported signed
        // out.
        if !store.update_if_unchanged(&updated, version).await? {
            return lost_the_row(store, fetcher, nonces, ctx, &updated, now).await;
        }
        // Logged because a refresh is otherwise INVISIBLE: it rotates both
        // tokens and is the one path that can silently end a session, but it
        // happens inside an ordinary page load. No token material is logged —
        // only that it happened, and when the replacement expires.
        tracing::info!(
            sub = %updated.sub,
            expires_at = ?updated.expires_at,
            "refreshed the OAuth session"
        );
        return Ok(updated);
    }

    match token::classify_refresh_failure(outcome.status, &outcome.body) {
        RefreshFailure::Transient => {
            // Network, 5xx, anything unrecognised: leave the stored tokens
            // exactly as they are and fail THIS request. Deleting here would log
            // someone out for a server hiccup.
            bail!(
                "refresh for {} failed transiently (status {}); the session is left intact",
                session.sub,
                outcome.status
            )
        }
        RefreshFailure::SessionInvalid => {
            // Before concluding the grant is dead, check whether another PROCESS
            // refreshed it while we held only an in-process lock. If the stored
            // refresh token has changed, ours was simply stale and theirs is
            // live — use it rather than deleting a working session.
            if let Some(current) = store.get(&session.sub).await? {
                if current.refresh_token != session.refresh_token {
                    return Ok(current);
                }
            }
            store.delete(&session.sub).await?;
            bail!(
                "refresh for {} was rejected as invalid_grant; the session has been \
                 removed and the user must log in again",
                session.sub
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_auth::AuthMethod;
    use crate::keys::SigningKey;
    use crate::net::Fetcher;
    use crate::store::memory::{MemoryNonces, MemorySessions, MemoryVersion};
    use crate::store::{Session, SessionStore};
    use crate::testing::{spawn_tls, test_host_override, TestResponse};
    use crate::token::TokenResponse;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const NOW: i64 = 1_700_000_000;

    fn session() -> Session {
        Session {
            sub: DID.into(),
            issuer: "https://auth.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: r#"{"kty":"EC","d":"k"}"#.into(),
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto transition:generic".into(),
            expires_at: Some(NOW + 60),
        }
    }

    fn response() -> TokenResponse {
        TokenResponse {
            access_token: "new-access".into(),
            refresh_token: Some("new-refresh".into()),
            token_type: "DPoP".into(),
            granted_scope: "atproto transition:generic".into(),
            sub: DID.into(),
            expires_in: Some(3600),
        }
    }

    #[test]
    fn a_refresh_replaces_both_tokens_and_the_expiry() {
        let updated = apply_refresh(&session(), &response(), NOW).unwrap();
        assert_eq!(updated.access_token, "new-access");
        assert_eq!(updated.refresh_token, "new-refresh");
        assert_eq!(updated.expires_at, Some(NOW + 3600));
    }

    /// **Rotation is expected but not guaranteed.** A response omitting
    /// `refresh_token` means keep the one we have — storing an empty string
    /// would destroy the session on the next refresh with no way to tell why.
    #[test]
    fn an_omitted_refresh_token_keeps_the_existing_one() {
        let mut response = response();
        response.refresh_token = None;
        let updated = apply_refresh(&session(), &response, NOW).unwrap();
        assert_eq!(updated.refresh_token, "old-refresh");
        assert_eq!(
            updated.access_token, "new-access",
            "the access token still rotates"
        );
    }

    /// `expires_in` is optional, and absent means no proactive refresh rather
    /// than an invented deadline.
    #[test]
    fn an_omitted_expiry_clears_rather_than_invents_one() {
        let mut response = response();
        response.expires_in = None;
        assert_eq!(
            apply_refresh(&session(), &response, NOW)
                .unwrap()
                .expires_at,
            None
        );
    }

    /// **A refresh must not be able to move a session to another account.**
    /// The reference re-checks `sub` on the refresh response for this reason.
    #[test]
    fn a_refresh_for_a_different_subject_is_rejected() {
        let mut response = response();
        response.sub = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(apply_refresh(&session(), &response, NOW).is_err());
    }

    /// A narrowed grant must be recorded, not silently kept at the old value —
    /// otherwise writes start failing with nothing to explain it.
    #[test]
    fn the_granted_scope_is_taken_from_the_response() {
        let mut response = response();
        response.granted_scope = "atproto".into();
        assert_eq!(
            apply_refresh(&session(), &response, NOW)
                .unwrap()
                .granted_scope,
            "atproto"
        );
    }

    /// The DPoP key and the PDS are properties of the session, not of any one
    /// token response; a refresh must leave them alone.
    #[test]
    fn a_refresh_preserves_the_session_key_and_audience() {
        let updated = apply_refresh(&session(), &response(), NOW).unwrap();
        assert_eq!(updated.dpop_key_jwk, session().dpop_key_jwk);
        assert_eq!(updated.aud, session().aud);
        assert_eq!(updated.issuer, session().issuer);
        assert_eq!(updated.sub, session().sub);
    }

    // ── the per-subject lock ─────────────────────────────────────────────────

    /// Two concurrent refreshes of the SAME subject must not overlap: both would
    /// present the same single-use refresh token, and the loser's
    /// `invalid_grant` typically revokes the winner's new tokens too.
    #[tokio::test]
    async fn the_same_subject_is_serialized() {
        let locks = RefreshLocks::default();
        let held = locks.lock(DID).await;

        let second = locks.lock(DID);
        tokio::pin!(second);
        assert!(
            futures_lite_poll_pending(&mut second),
            "a second holder acquired the lock while the first held it"
        );
        drop(held);
        // Once released, the waiter proceeds.
        let _ = second.await;
    }

    /// Different subjects must NOT block each other, or one slow refresh stalls
    /// every other account.
    #[tokio::test]
    async fn different_subjects_do_not_block_each_other() {
        let locks = RefreshLocks::default();
        let _a = locks.lock(DID).await;
        let b = locks.lock("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        tokio::pin!(b);
        assert!(
            !futures_lite_poll_pending(&mut b),
            "an unrelated subject was blocked"
        );
    }

    /// Poll a future once; true if it is still pending.
    fn futures_lite_poll_pending<F: std::future::Future>(fut: &mut std::pin::Pin<&mut F>) -> bool {
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        matches!(fut.as_mut().poll(&mut cx), Poll::Pending)
    }

    // ── the refresh's write vs a concurrent sign-out ─────────────────────────

    /// The `/token` reply that rotates to `rotated-refresh`.
    fn rotation() -> TestResponse {
        TestResponse::json(
            200,
            serde_json::json!({
                "access_token": "rotated-access",
                "refresh_token": "rotated-refresh",
                "token_type": "DPoP",
                "scope": "atproto",
                "sub": DID,
                "expires_in": 3600,
            })
            .to_string(),
        )
    }

    /// An authorization server over real TLS whose `/token` answers `token`
    /// and whose `/revoke` accepts. The Fetcher that reaches it, its base URL,
    /// and the request log.
    async fn token_server_answering(
        token: TestResponse,
    ) -> (
        Fetcher,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let (addr, log) = spawn_tls(move |_| {
            let mut r = std::collections::HashMap::new();
            r.insert("/token".to_string(), vec![token]);
            r.insert("/revoke".to_string(), vec![TestResponse::json(200, "{}")]);
            r
        })
        .await;
        let fetcher = Fetcher::default();
        test_host_override(&fetcher, "as-e2e.test", addr);
        (fetcher, format!("https://as-e2e.test:{}", addr.port()), log)
    }

    /// An authorization server over real TLS whose `/token` rotates to
    /// `rotated-refresh` and whose `/revoke` accepts.
    async fn token_server() -> (
        Fetcher,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        token_server_answering(rotation()).await
    }

    /// An expired session stored in memory, and the version read back.
    async fn stored_stale() -> (MemorySessions, Session, MemoryVersion) {
        let store = MemorySessions::new();
        let stale = Session {
            dpop_key_jwk: SigningKey::generate("session-dpop").to_jwk_json().unwrap(),
            expires_at: Some(NOW - 1),
            ..session()
        };
        store.put(&stale).await.unwrap();
        let (read, version) = store.get_versioned(DID).await.unwrap().unwrap();
        (store, read, version)
    }

    fn ctx<'a>(token: &'a str, revoke: &'a str) -> RefreshContext<'a> {
        RefreshContext {
            token_endpoint: token,
            client_id: "http://localhost",
            auth_method: AuthMethod::None,
            client_key: None,
            revocation_endpoint: Some(revoke),
        }
    }

    fn revoke_requests(log: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST /revoke"))
            .cloned()
            .collect()
    }

    /// **A refresh must not resurrect a session signed out while it ran.**
    ///
    /// The refresh lock is in-process; a sign-out does not take it (and the
    /// operator's revoke-all runs in another process). The refresh's write was
    /// an upsert, so a sign-out that deleted the row while the token request
    /// was in flight was undone: the session came back holding the fresh
    /// tokens, after being reported signed out — and on Fly no later pass
    /// would ever see it. The fresh tokens belong to no one, so they are
    /// revoked instead.
    #[tokio::test]
    async fn a_refresh_does_not_resurrect_a_session_signed_out_mid_refresh() {
        let (fetcher, base, log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;

        // The sign-out lands while the refresh is in flight.
        store.delete(DID).await.unwrap();

        let result = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await;

        assert!(
            store.get(DID).await.unwrap().is_none(),
            "the refresh RESURRECTED a signed-out session"
        );
        let err = result.expect_err("a signed-out session must not be handed back");
        assert!(
            format!("{err:#}").contains("signed out while being refreshed"),
            "{err:#}"
        );
        let seen = log.lock().unwrap().join("\n---\n");
        assert!(
            seen.contains("POST /revoke") && seen.contains("token=rotated-refresh"),
            "the orphaned fresh token was left live:\n{seen}"
        );
    }

    /// **No lost update, and no orphaned grant:** a row another writer
    /// rewrote while this refresh ran (in practice a RE-LOGIN — a concurrent
    /// refresh of the same single-use token cannot also have succeeded) is
    /// kept, not overwritten, and theirs is what the caller gets. The tokens
    /// THIS refresh obtained belong to the old grant, are stored nowhere, and
    /// would stay live at the PDS — so they are revoked.
    #[tokio::test]
    async fn a_refresh_does_not_overwrite_a_concurrent_rotation() {
        let (fetcher, base, log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;

        let theirs = Session {
            refresh_token: "their-refresh".into(),
            access_token: "their-access".into(),
            expires_at: Some(NOW + 3600),
            ..session.clone()
        };
        store.put(&theirs).await.unwrap();

        let got = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect("a concurrent rotation is not an error");

        let stored = store.get(DID).await.unwrap().unwrap();
        assert_eq!(
            stored.refresh_token, "their-refresh",
            "the other writer's rotation was overwritten"
        );
        assert_eq!(got.refresh_token, "their-refresh");
        let revokes: Vec<String> = log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST /revoke"))
            .cloned()
            .collect();
        assert!(
            revokes.iter().any(|r| r.contains("token=rotated-refresh")),
            "the refresh's own fresh token was left live, stored nowhere:\n{revokes:#?}"
        );
        assert!(
            !revokes.iter().any(|r| r.contains("their-refresh")),
            "revoked the OTHER writer's live token:\n{revokes:#?}"
        );
    }

    /// The ordinary refresh still writes.
    #[tokio::test]
    async fn an_uncontested_refresh_stores_the_rotated_tokens() {
        let (fetcher, base, _log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;

        let got = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect("refresh");
        assert_eq!(got.refresh_token, "rotated-refresh");
        assert_eq!(
            store.get(DID).await.unwrap().unwrap().refresh_token,
            "rotated-refresh"
        );
    }

    // ── what a refresh failure means, end to end ─────────────────────────────

    /// **A refresh whose `sub` moved leaves the stored session untouched.** The
    /// token endpoint answering for ANOTHER account (a compromised or confused
    /// authorization server) must not rebind the session: the refresh fails,
    /// the stored row is exactly what it was, and nothing is sent to `/revoke`
    /// (there is no orphan of OURS to revoke; the stored grant is still live).
    #[tokio::test]
    async fn a_refresh_whose_sub_moved_leaves_the_stored_session_untouched() {
        let other = TestResponse::json(
            200,
            serde_json::json!({
                "access_token": "other-access",
                "refresh_token": "other-refresh",
                "token_type": "DPoP",
                "scope": "atproto",
                "sub": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "expires_in": 3600,
            })
            .to_string(),
        );
        let (fetcher, base, log) = token_server_answering(other).await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;

        let err = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect_err("a refresh for another subject must fail");
        assert!(format!("{err:#}").contains("refusing to rebind"), "{err:#}");

        let (stored, after) = store.get_versioned(DID).await.unwrap().unwrap();
        assert_eq!(stored, session, "the stored session was changed");
        assert!(after == version, "the stored row was rewritten");
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|r| r.starts_with("POST /token")),
            "the refresh never reached the token endpoint, so this proves nothing"
        );
        assert!(
            revoke_requests(&log).is_empty(),
            "a revocation was sent: {:#?}",
            revoke_requests(&log)
        );
    }

    /// **Only `invalid_grant` deletes.** A `400 invalid_grant` means the grant
    /// is dead: the session is removed and the user must log in again. A `5xx`
    /// is a server hiccup: the session is left exactly as it was. Two servers,
    /// one assertion each.
    #[tokio::test]
    async fn an_invalid_grant_refresh_deletes_the_session_and_a_5xx_leaves_it_intact() {
        // invalid_grant: deleted.
        let (fetcher, base, _log) =
            token_server_answering(TestResponse::json(400, r#"{"error":"invalid_grant"}"#)).await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;
        let err = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect_err("a dead grant is an error");
        assert!(format!("{err:#}").contains("invalid_grant"), "{err:#}");
        assert!(
            store.get(DID).await.unwrap().is_none(),
            "a dead grant's session was kept"
        );

        // 5xx: intact.
        let (fetcher, base, _log) =
            token_server_answering(TestResponse::json(503, r#"{"error":"invalid_grant"}"#)).await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;
        let err = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect_err("a 5xx is an error for this request");
        assert!(format!("{err:#}").contains("transiently"), "{err:#}");
        let (stored, after) = store
            .get_versioned(DID)
            .await
            .unwrap()
            .expect("a 5xx logged the user out");
        assert_eq!(stored, session, "a 5xx changed the stored session");
        assert!(after == version, "a 5xx rewrote the stored row");
    }

    /// **A rejected refresh adopts another process's rotation instead of
    /// deleting.** The refresh lock is in-process; another process (a second
    /// instance, a rolling deploy) can refresh the same session meanwhile. Our
    /// stale refresh token then gets `400 invalid_grant` — not because the
    /// grant is dead, but because it was already rotated. The stored row holds
    /// the live token: hand it back rather than deleting a working session.
    #[tokio::test]
    async fn a_rejected_refresh_adopts_another_processes_rotation_instead_of_deleting() {
        let (fetcher, base, _log) =
            token_server_answering(TestResponse::json(400, r#"{"error":"invalid_grant"}"#)).await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, session, version) = stored_stale().await;

        // Another process rotated the row after we read it.
        let theirs = Session {
            refresh_token: "their-refresh".into(),
            access_token: "their-access".into(),
            expires_at: Some(NOW + 3600),
            ..session.clone()
        };
        store.put(&theirs).await.unwrap();

        let got = refresh_locked(
            &store,
            &fetcher,
            &MemoryNonces::new(),
            &session,
            &version,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect("a stale token rejected after another process rotated is not a dead grant");
        assert_eq!(got, theirs, "the caller did not get the live session");
        assert_eq!(
            store.get(DID).await.unwrap(),
            Some(theirs),
            "the live session was deleted or changed"
        );
    }

    // ── valid_session, the entry point ───────────────────────────────────────

    /// A session that is not close to expiry is returned as stored, without a
    /// request (the endpoint here would refuse one: it is on loopback).
    #[tokio::test]
    async fn a_fresh_session_is_returned_without_a_refresh() {
        let store = MemorySessions::new();
        let fresh = Session {
            expires_at: Some(NOW + 3600),
            ..session()
        };
        store.put(&fresh).await.unwrap();
        let got = valid_session(
            &store,
            &Fetcher::default(),
            &MemoryNonces::new(),
            &RefreshLocks::default(),
            DID,
            &ctx("https://127.0.0.1/token", "https://127.0.0.1/revoke"),
            NOW,
        )
        .await
        .expect("a fresh session needs no refresh");
        assert_eq!(got, fresh);
    }

    /// A stale session is refreshed, stored, and the refreshed one returned; a
    /// subject with no session is an error.
    #[tokio::test]
    async fn a_stale_session_is_refreshed_and_an_absent_one_is_an_error() {
        let (fetcher, base, _log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, _, _) = stored_stale().await;
        let locks = RefreshLocks::default();
        let nonces = MemoryNonces::new();

        let got = valid_session(
            &store,
            &fetcher,
            &nonces,
            &locks,
            DID,
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect("refresh");
        assert_eq!(got.refresh_token, "rotated-refresh");
        assert_eq!(got.expires_at, Some(NOW + 3600));
        assert_eq!(store.get(DID).await.unwrap(), Some(got));

        let err = valid_session(
            &store,
            &fetcher,
            &nonces,
            &locks,
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            &ctx(&token, &revoke),
            NOW,
        )
        .await
        .expect_err("no session");
        assert!(format!("{err:#}").contains("no session for"), "{err:#}");
    }

    /// **A refresh that waited on the lock uses the winner's tokens.** Whoever
    /// held the lock may have refreshed while we waited; presenting the token
    /// they just replaced would burn it (single-use). So the session is re-read
    /// under the lock, and a now-fresh one is returned without a request.
    #[tokio::test]
    async fn a_refresh_that_waited_on_the_lock_uses_the_winners_tokens() {
        let (fetcher, base, log) = token_server().await;
        let (token, revoke) = (format!("{base}/token"), format!("{base}/revoke"));
        let (store, stale, _) = stored_stale().await;
        let locks = RefreshLocks::default();
        let nonces = MemoryNonces::new();

        // Another refresh holds the lock...
        let held = locks.lock(DID).await;
        let ctx = ctx(&token, &revoke);
        let waiting = valid_session(&store, &fetcher, &nonces, &locks, DID, &ctx, NOW);
        tokio::pin!(waiting);
        assert!(
            futures_lite_poll_pending(&mut waiting),
            "the refresh did not wait for the lock"
        );
        // ...and stores its rotation before releasing it.
        let winners = Session {
            refresh_token: "winners-refresh".into(),
            access_token: "winners-access".into(),
            expires_at: Some(NOW + 3600),
            ..stale
        };
        store.put(&winners).await.unwrap();
        drop(held);

        let got = waiting.await.expect("the winner's session");
        assert_eq!(got, winners);
        assert!(
            !log.lock()
                .unwrap()
                .iter()
                .any(|r| r.starts_with("POST /token")),
            "presented the refresh token the winner had already replaced"
        );
    }

    /// The refresh future is `Send` for any stores, so it can run on a
    /// multi-threaded runtime. Compile-time.
    #[test]
    fn the_valid_session_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn generic<S: SessionStore, N: crate::store::NonceStore>(store: &S, nonces: &N) {
            let fetcher = Fetcher::default();
            let locks = RefreshLocks::default();
            let ctx = ctx("https://a.example/token", "https://a.example/revoke");
            assert_send(&valid_session(
                store, &fetcher, nonces, &locks, DID, &ctx, NOW,
            ));
        }
        generic(&MemorySessions::new(), &MemoryNonces::new());
    }
}
