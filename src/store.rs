//! Storage seams: what calamus needs persisted, as traits the caller
//! implements over its own storage.
//!
//! calamus has no persistence of its own. FeatherReader implements these over
//! SQLite; [`memory`] has in-process implementations for tests and for a
//! single-process caller, and [`Discard`] is a session store that keeps nothing,
//! for a login that only wants to know who the user is.
//!
//! Three seams: [`NonceStore`] (DPoP nonces per origin), [`PendingLoginStore`]
//! (logins between PAR and the callback) and [`SessionStore`] (the tokens).
//! Their exact semantics are pinned by a contract suite in
//! `calamus::testing::store_contract` (feature `test-util`), which an
//! implementation over a database runs against its own store.
//!
//! What a database implementation keeps for itself: its schema, and any
//! encryption of the secrets at rest (FeatherReader seals the PKCE verifier, the
//! DPoP keys and both tokens, bound to the row's other columns). calamus only
//! ever sees plaintext values.
//!
//! The traits use `async fn`-in-trait with the `Send` bound spelled out on the
//! returned future (like [`crate::resolve::DnsResolver`]), so a caller can spawn
//! any calamus future on a multi-threaded runtime.

use std::future::Future;

use anyhow::Result;

use crate::client_auth::AuthMethod;

/// The latest DPoP nonce each server origin handed out (RFC 9449 §8, §9).
///
/// [`crate::request::send_with_dpop`] reads the stored nonce before the first
/// attempt and stores every nonce a response offers, success or failure.
/// Keys are origins as [`crate::discovery::origin_of`] renders them
/// (`https://host[:port]`), never full URLs: the nonce belongs to the server, so
/// PAR and token on one issuer share it.
///
/// **Writes happen before any authentication**: PAR runs for whatever handle a
/// visitor typed, so the set of origins is attacker-influenced. An
/// implementation should expire entries that have not been touched for a while
/// (FeatherReader sweeps nonces untouched for longer than a fixed age; a stale
/// nonce is worthless anyway, since the server issues a fresh one with its next
/// challenge). `now` is passed to [`NonceStore::put`] for exactly that.
///
/// Ported from FeatherReader's `store::{get_nonce, put_nonce}`.
pub trait NonceStore: Send + Sync {
    /// The stored nonce for `origin`, if any.
    fn get(&self, origin: &str) -> impl Future<Output = Result<Option<String>>> + Send;

    /// Record `nonce` as the latest for `origin`, replacing any earlier one
    /// (servers rotate nonces). `now` is the write time in Unix seconds, for an
    /// implementation's expiry.
    fn put(&self, origin: &str, nonce: &str, now: i64) -> impl Future<Output = Result<()>> + Send;
}

/// An in-flight login: what PAR pushed, kept until the callback consumes it.
///
/// FeatherReader's `store::PendingAuth`, with `auth_method` typed (FeatherReader
/// stores its wire name, [`AuthMethod::as_str`], and parses it back with
/// `FromStr`). `pkce_verifier` and `dpop_key_jwk` are secrets, and `Debug`
/// prints them (and the binding hash) as `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingLogin {
    /// The `state` pushed in PAR; the key the callback finds this by.
    pub state: String,
    /// [`crate::flow::binding_hash`] of the browser-binding cookie set when the
    /// login started.
    pub browser_binding_hash: String,
    /// The PKCE verifier for the challenge pushed in PAR.
    pub pkce_verifier: String,
    /// The DPoP key the login was started with, as JWK JSON; the session keeps it.
    pub dpop_key_jwk: String,
    /// The authorization server the request was pushed to; the callback's `iss`
    /// must equal it.
    pub issuer: String,
    /// The account's PDS, as resolved when the login started.
    pub pds_url: String,
    /// The DID the login is for; the token response's `sub` must equal it.
    pub did: String,
    /// How the client authenticated at PAR; the code exchange must match.
    pub auth_method: AuthMethod,
    /// The `kid` of the client key that signed the PAR assertion, if any.
    pub auth_kid: Option<String>,
    /// The redirect URI pushed in PAR; the code exchange must repeat it.
    pub redirect_uri: String,
    /// The scope requested in PAR.
    pub requested_scope: String,
    /// The `request_uri` PAR returned.
    pub request_uri: String,
    /// Where the application sends the browser after the login, if anywhere.
    pub app_return_to: Option<String>,
    /// Unix seconds; the row is expired AT this second.
    pub expires_at: i64,
}

/// Logins between PAR and the callback.
///
/// The callback's `state` is global to the server, not per browser, so this is
/// a server-wide table; [`crate::flow::complete_callback`] pairs it with the
/// browser binding.
///
/// **Writes happen before any authentication** (a login starts for whatever
/// handle a visitor typed), so an implementation should sweep expired rows: an
/// abandoned login is never taken. FeatherReader sweeps `expires_at <= now`
/// periodically.
///
/// Ported from FeatherReader's `store::{put_pending, take_pending}`.
pub trait PendingLoginStore: Send + Sync {
    /// Record a login. **Refuses** (`Err`) a `state` that is already pending
    /// rather than replacing it: states are fresh random values, so a collision
    /// is a bug or an attack, and replacing the row would let one login
    /// overwrite another's PKCE verifier and key.
    fn put(&self, login: &PendingLogin) -> impl Future<Output = Result<()>> + Send;

    /// **Consume** the login for `state`: return it and remove it, atomically,
    /// so two concurrent callbacks cannot both get it (both would exchange the
    /// same `code`, and the authorization server may then revoke everything
    /// issued for it).
    ///
    /// A row with `expires_at <= now` is removed too, and reported absent, so
    /// an expired flow cannot be probed for after the fact.
    fn take(
        &self,
        state: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<PendingLogin>>> + Send;
}

/// An authenticated account's tokens.
///
/// FeatherReader's `store::OAuthSession`. `dpop_key_jwk`, `access_token` and
/// `refresh_token` are secrets, and `Debug` prints them as `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    /// The account's DID; the key a session is stored under.
    pub sub: String,
    /// The authorization server that issued the grant.
    pub issuer: String,
    /// The PDS the tokens are for (the resource server).
    pub aud: String,
    /// The session's DPoP key, as JWK JSON. Every request on this grant is
    /// proved with it.
    pub dpop_key_jwk: String,
    /// The current access token.
    pub access_token: String,
    /// The current refresh token. Single-use: every refresh rotates it.
    pub refresh_token: String,
    /// Always `DPoP` for atproto.
    pub token_type: String,
    /// The scope the server granted, which may be narrower than requested.
    pub granted_scope: String,
    /// When the access token expires (Unix seconds), if the server said.
    pub expires_at: Option<i64>,
}

/// What `Debug` prints in place of a secret.
const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogin")
            .field("state", &self.state)
            .field("browser_binding_hash", &REDACTED)
            .field("pkce_verifier", &REDACTED)
            .field("dpop_key_jwk", &REDACTED)
            .field("issuer", &self.issuer)
            .field("pds_url", &self.pds_url)
            .field("did", &self.did)
            .field("auth_method", &self.auth_method)
            .field("auth_kid", &self.auth_kid)
            .field("redirect_uri", &self.redirect_uri)
            .field("requested_scope", &self.requested_scope)
            .field("request_uri", &self.request_uri)
            .field("app_return_to", &self.app_return_to)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("sub", &self.sub)
            .field("issuer", &self.issuer)
            .field("aud", &self.aud)
            .field("dpop_key_jwk", &REDACTED)
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("granted_scope", &self.granted_scope)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Sessions, one per subject DID.
///
/// The refresh and sign-out races are decided here, by the two conditional
/// writes: a refresh writes only over the row it read
/// ([`SessionStore::update_if_unchanged`]), so it cannot resurrect a session
/// signed out while it ran or overwrite a concurrent re-login; and a sign-out
/// deletes only the row whose tokens it revoked
/// ([`SessionStore::delete_if_unchanged`]), so a token rotated in between is
/// never dropped unrevoked.
///
/// Ported from FeatherReader's `store::{get_session, get_session_versioned,
/// put_session, update_session_if_unchanged, delete_session,
/// delete_session_if_unchanged}`.
pub trait SessionStore: Send + Sync {
    /// Identifies one write of one row. **Any** write changes it, even one that
    /// stores identical values (FeatherReader's is the row's ciphertexts, which
    /// a write re-encrypts under a fresh nonce). Opaque to calamus: it is only
    /// ever compared, and handed back to the store that issued it.
    ///
    /// **Never reused for a subject**, including across a delete and a
    /// re-insert: a version read before a sign-out must not match the row a
    /// later login writes, even with identical values (ABA). A counter per row
    /// that restarts at 1 on insert breaks this; a counter per store, a random
    /// value, or FeatherReader's fresh-nonce ciphertexts do not.
    ///
    /// `Sync` as well as `Send` because the refresh and sign-out futures hold a
    /// reference to one across an await.
    type Version: Clone + PartialEq + Send + Sync;

    /// The session for `sub`, if any.
    fn get(&self, sub: &str) -> impl Future<Output = Result<Option<Session>>> + Send;

    /// The session for `sub` and the [`Version`](SessionStore::Version) of the
    /// row it was read from, from ONE read, so the version is the one these
    /// tokens came from.
    fn get_versioned(
        &self,
        sub: &str,
    ) -> impl Future<Output = Result<Option<(Session, Self::Version)>>> + Send;

    /// Store or REPLACE the session for `session.sub`. An upsert: logging in
    /// again (a second browser, re-auth after expiry) is normal.
    fn put(&self, session: &Session) -> impl Future<Output = Result<()>> + Send;

    /// Replace the session for `session.sub` ONLY if its row is still at
    /// `version`, atomically. `true` if written; `false` if the row is gone or
    /// was rewritten since, and then nothing is written. Never an upsert.
    fn update_if_unchanged(
        &self,
        session: &Session,
        version: &Self::Version,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// Delete the session for `sub`. `true` if one existed.
    fn delete(&self, sub: &str) -> impl Future<Output = Result<bool>> + Send;

    /// Delete the session for `sub` ONLY if its row is still at `version`,
    /// atomically. `true` if deleted; `false` if gone or rewritten since.
    fn delete_if_unchanged(
        &self,
        sub: &str,
        version: &Self::Version,
    ) -> impl Future<Output = Result<bool>> + Send;
}

/// A [`SessionStore`] that keeps nothing: `put` succeeds and is dropped, every
/// read is empty, and no conditional write or delete reports a row.
///
/// For a login that only establishes who the user is (sign in with atproto)
/// and never calls their PDS: the tokens are not wanted, so nothing should
/// hold them. A refresh or sign-out against it finds no session.
///
/// **Discarding the tokens does not end the grant.** The authorization server
/// still holds it, and the refresh token stays live there until it expires.
/// Nothing can leak from a store that holds nothing, but a caller that wants
/// the grant gone should revoke it once the identity is established: keep the
/// [`Session`] the login returned for that one call
/// ([`crate::revoke::revoke_tokens`]), then drop it.
#[derive(Debug, Default, Clone, Copy)]
pub struct Discard;

impl SessionStore for Discard {
    type Version = ();

    async fn get(&self, _sub: &str) -> Result<Option<Session>> {
        Ok(None)
    }

    async fn get_versioned(&self, _sub: &str) -> Result<Option<(Session, ())>> {
        Ok(None)
    }

    async fn put(&self, _session: &Session) -> Result<()> {
        Ok(())
    }

    async fn update_if_unchanged(&self, _session: &Session, _version: &()) -> Result<bool> {
        Ok(false)
    }

    async fn delete(&self, _sub: &str) -> Result<bool> {
        Ok(false)
    }

    async fn delete_if_unchanged(&self, _sub: &str, _version: &()) -> Result<bool> {
        Ok(false)
    }
}

/// In-process stores: a `Mutex<HashMap>` each.
///
/// For tests, and for a caller with one process and no need for its state to
/// survive a restart.
pub mod memory {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use anyhow::{bail, Result};

    use super::{NonceStore, PendingLogin, PendingLoginStore, Session, SessionStore};

    /// Lock `mutex`, recovering a poisoned lock: every write here is one map
    /// operation, so a panic elsewhere while holding it cannot leave a
    /// half-written entry.
    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// [`NonceStore`] in memory.
    ///
    /// Unbounded by itself, and its writes are pre-authentication (see
    /// [`NonceStore`]): a long-running caller should call
    /// [`MemoryNonces::sweep`] periodically.
    #[derive(Debug, Default)]
    pub struct MemoryNonces {
        /// origin -> (nonce, when it was last written).
        nonces: Mutex<HashMap<String, (String, i64)>>,
    }

    impl MemoryNonces {
        /// An empty store.
        pub fn new() -> Self {
            Self::default()
        }

        /// Drop every nonce last written at or before `cutoff` (Unix seconds).
        /// Returns how many went. FeatherReader's `store::sweep_stale_nonces`.
        pub fn sweep(&self, cutoff: i64) -> usize {
            let mut nonces = lock(&self.nonces);
            let before = nonces.len();
            nonces.retain(|_, (_, updated_at)| *updated_at > cutoff);
            before - nonces.len()
        }
    }

    impl NonceStore for MemoryNonces {
        async fn get(&self, origin: &str) -> Result<Option<String>> {
            Ok(lock(&self.nonces)
                .get(origin)
                .map(|(nonce, _)| nonce.clone()))
        }

        async fn put(&self, origin: &str, nonce: &str, now: i64) -> Result<()> {
            lock(&self.nonces).insert(origin.to_string(), (nonce.to_string(), now));
            Ok(())
        }
    }

    /// [`PendingLoginStore`] in memory. `take` is atomic by construction: the
    /// lookup and the removal are one `remove` under the lock.
    ///
    /// Unbounded by itself, and its writes are pre-authentication (see
    /// [`PendingLoginStore`]): a long-running caller should call
    /// [`MemoryPendingLogins::sweep`] periodically.
    #[derive(Default)]
    pub struct MemoryPendingLogins {
        logins: Mutex<HashMap<String, PendingLogin>>,
    }

    /// The count only: the rows hold secrets.
    impl std::fmt::Debug for MemoryPendingLogins {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemoryPendingLogins")
                .field("pending", &lock(&self.logins).len())
                .finish()
        }
    }

    impl MemoryPendingLogins {
        /// An empty store.
        pub fn new() -> Self {
            Self::default()
        }

        /// Drop every login expired at `now` (`expires_at <= now`). Returns how
        /// many went. FeatherReader's `store::sweep_expired_pending`.
        pub fn sweep(&self, now: i64) -> usize {
            let mut logins = lock(&self.logins);
            let before = logins.len();
            logins.retain(|_, login| login.expires_at > now);
            before - logins.len()
        }
    }

    impl PendingLoginStore for MemoryPendingLogins {
        async fn put(&self, login: &PendingLogin) -> Result<()> {
            let mut logins = lock(&self.logins);
            if logins.contains_key(&login.state) {
                bail!("a login is already pending under that `state`");
            }
            logins.insert(login.state.clone(), login.clone());
            Ok(())
        }

        async fn take(&self, state: &str, now: i64) -> Result<Option<PendingLogin>> {
            // Removed whether or not it has expired: an expired flow is gone.
            let taken = lock(&self.logins).remove(state);
            // Expired AT `expires_at`, not one second later.
            Ok(taken.filter(|login| login.expires_at > now))
        }
    }

    /// The [`SessionStore::Version`] of a [`MemorySessions`] row: the number of
    /// the write that produced it.
    ///
    /// Numbered from one counter for the whole process, so a version from one
    /// store never matches a row in another.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryVersion(u64);

    /// Every write of every [`MemorySessions`] takes the next number.
    static WRITES: AtomicU64 = AtomicU64::new(1);

    fn next_version() -> MemoryVersion {
        MemoryVersion(WRITES.fetch_add(1, Ordering::Relaxed))
    }

    /// [`SessionStore`] in memory. Each conditional write is one comparison and
    /// one map operation under the lock, so it is atomic.
    #[derive(Default)]
    pub struct MemorySessions {
        /// sub -> (session, the write that produced it).
        sessions: Mutex<HashMap<String, (Session, MemoryVersion)>>,
    }

    /// The count only: the rows hold secrets.
    impl std::fmt::Debug for MemorySessions {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemorySessions")
                .field("sessions", &lock(&self.sessions).len())
                .finish()
        }
    }

    impl MemorySessions {
        /// An empty store.
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl SessionStore for MemorySessions {
        type Version = MemoryVersion;

        async fn get(&self, sub: &str) -> Result<Option<Session>> {
            Ok(lock(&self.sessions).get(sub).map(|(s, _)| s.clone()))
        }

        async fn get_versioned(&self, sub: &str) -> Result<Option<(Session, MemoryVersion)>> {
            Ok(lock(&self.sessions).get(sub).cloned())
        }

        async fn put(&self, session: &Session) -> Result<()> {
            lock(&self.sessions).insert(session.sub.clone(), (session.clone(), next_version()));
            Ok(())
        }

        async fn update_if_unchanged(
            &self,
            session: &Session,
            version: &MemoryVersion,
        ) -> Result<bool> {
            let mut sessions = lock(&self.sessions);
            match sessions.get_mut(&session.sub) {
                Some(row) if row.1 == *version => {
                    *row = (session.clone(), next_version());
                    Ok(true)
                }
                _ => Ok(false),
            }
        }

        async fn delete(&self, sub: &str) -> Result<bool> {
            Ok(lock(&self.sessions).remove(sub).is_some())
        }

        async fn delete_if_unchanged(&self, sub: &str, version: &MemoryVersion) -> Result<bool> {
            let mut sessions = lock(&self.sessions);
            if sessions.get(sub).is_some_and(|(_, v)| v == version) {
                sessions.remove(sub);
                return Ok(true);
            }
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::{MemoryNonces, MemoryPendingLogins, MemorySessions};
    use super::*;

    const NOW: i64 = 1_700_000_000;

    /// FeatherReader's `store::tests::nonces_are_stored_and_replaced_per_origin`,
    /// against the in-memory store: absent until put, one value per origin, and
    /// a later value replaces the earlier (servers rotate nonces).
    #[tokio::test]
    async fn memory_nonces_round_trip_per_origin_and_replace() -> anyhow::Result<()> {
        let nonces = MemoryNonces::new();
        assert_eq!(nonces.get("https://a.example").await?, None);

        nonces.put("https://a.example", "n1", NOW).await?;
        nonces.put("https://b.example", "n2", NOW).await?;
        assert_eq!(
            nonces.get("https://a.example").await?.as_deref(),
            Some("n1")
        );
        assert_eq!(
            nonces.get("https://b.example").await?.as_deref(),
            Some("n2")
        );

        // Rotation: servers rotate nonces, so a later value replaces the earlier.
        nonces.put("https://a.example", "n3", NOW).await?;
        assert_eq!(
            nonces.get("https://a.example").await?.as_deref(),
            Some("n3")
        );
        assert_eq!(
            nonces.get("https://b.example").await?.as_deref(),
            Some("n2"),
            "replacing one origin's nonce touched another's"
        );
        Ok(())
    }

    /// The sweep drops exactly the nonces untouched since the cutoff (inclusive,
    /// like FeatherReader's `sweep_stale_nonces`), and a `put` refreshes the age.
    #[tokio::test]
    async fn memory_nonces_sweep_only_what_is_stale() -> anyhow::Result<()> {
        let nonces = MemoryNonces::new();
        nonces.put("https://old.example", "o", NOW - 600).await?;
        nonces.put("https://edge.example", "e", NOW - 300).await?;
        nonces.put("https://new.example", "n", NOW).await?;
        nonces.put("https://moved.example", "m1", NOW - 900).await?;
        nonces.put("https://moved.example", "m2", NOW - 10).await?;

        assert_eq!(nonces.sweep(NOW - 300), 2);
        assert_eq!(nonces.get("https://old.example").await?, None);
        assert_eq!(nonces.get("https://edge.example").await?, None);
        assert_eq!(
            nonces.get("https://new.example").await?.as_deref(),
            Some("n")
        );
        assert_eq!(
            nonces.get("https://moved.example").await?.as_deref(),
            Some("m2")
        );
        Ok(())
    }

    // ── sessions and pending logins ─────────────────────────────────────────

    /// The contract suite in `calamus::testing::store_contract`, against the
    /// in-memory session store. FeatherReader runs the same suite against SQLite.
    #[tokio::test]
    async fn memory_sessions_meet_the_store_contract() {
        crate::testing::store_contract::sessions(&MemorySessions::new()).await;
    }

    /// `take` stays single-use under real parallelism.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn memory_pending_logins_take_is_atomic_across_threads() {
        crate::testing::store_contract::pending_take_is_atomic(
            std::sync::Arc::new(MemoryPendingLogins::new()),
            8,
            200,
        )
        .await;
    }

    /// The contract suite against the in-memory pending-login store.
    #[tokio::test]
    async fn memory_pending_logins_meet_the_store_contract() {
        crate::testing::store_contract::pending(&MemoryPendingLogins::new()).await;
    }

    fn a_login() -> PendingLogin {
        PendingLogin {
            state: "s".into(),
            browser_binding_hash: "h".into(),
            pkce_verifier: "v".into(),
            dpop_key_jwk: "{}".into(),
            issuer: "https://auth.example.com".into(),
            pds_url: "https://pds.example.com".into(),
            did: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            auth_method: crate::client_auth::AuthMethod::None,
            auth_kid: None,
            redirect_uri: "http://127.0.0.1/callback".into(),
            requested_scope: "atproto".into(),
            request_uri: "urn:x".into(),
            app_return_to: None,
            expires_at: NOW,
        }
    }

    fn a_session() -> Session {
        Session {
            sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz".into(),
            issuer: "https://auth.example.com".into(),
            aud: "https://pds.example.com".into(),
            dpop_key_jwk: "{}".into(),
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            token_type: "DPoP".into(),
            granted_scope: "atproto".into(),
            expires_at: None,
        }
    }

    /// The pending-login sweep drops exactly the rows expired at `now`
    /// (`expires_at <= now`, FeatherReader's `sweep_expired_pending`).
    #[tokio::test]
    async fn memory_pending_logins_sweep_only_what_is_expired() -> anyhow::Result<()> {
        let store = MemoryPendingLogins::new();
        for (state, expires_at) in [("old", NOW - 1), ("edge", NOW), ("live", NOW + 1)] {
            let mut login = a_login();
            login.state = state.into();
            login.expires_at = expires_at;
            store.put(&login).await?;
        }
        assert_eq!(store.sweep(NOW), 2);
        assert!(store.take("live", NOW).await?.is_some());
        assert!(store.take("old", NOW - 10).await?.is_none());
        assert!(store.take("edge", NOW - 10).await?.is_none());
        Ok(())
    }

    /// **No secret reaches a `Debug` rendering.** Sessions and pending logins
    /// end up in logs through `{:?}` (an `anyhow` context, a `tracing` field, a
    /// test failure); the tokens, the PKCE verifier and the private DPoP JWK
    /// must not. The non-secret identifiers stay, or the output is useless.
    #[tokio::test]
    async fn debug_output_redacts_every_secret() -> anyhow::Result<()> {
        let session = Session {
            dpop_key_jwk: r#"{"kty":"EC","d":"PRIVATE-D"}"#.into(),
            access_token: "SECRET-ACCESS".into(),
            refresh_token: "SECRET-REFRESH".into(),
            ..a_session()
        };
        let login = PendingLogin {
            pkce_verifier: "SECRET-VERIFIER".into(),
            dpop_key_jwk: r#"{"kty":"EC","d":"PENDING-D"}"#.into(),
            ..a_login()
        };
        let sessions = MemorySessions::new();
        sessions.put(&session).await?;
        let logins = MemoryPendingLogins::new();
        logins.put(&login).await?;

        let rendered = [
            format!("{session:?}"),
            format!("{session:#?}"),
            format!("{login:?}"),
            format!("{login:#?}"),
            format!("{sessions:?}"),
            format!("{logins:?}"),
            format!("{:?}", sessions.get_versioned(&session.sub).await?),
        ];
        for shown in &rendered {
            for secret in [
                "SECRET-ACCESS",
                "SECRET-REFRESH",
                "PRIVATE-D",
                "SECRET-VERIFIER",
                "PENDING-D",
            ] {
                assert!(!shown.contains(secret), "{secret} in {shown}");
            }
        }
        assert!(rendered[0].contains(&session.sub) && rendered[0].contains(&session.issuer));
        assert!(rendered[0].contains("<redacted>"), "{}", rendered[0]);
        assert!(rendered[2].contains(&login.state) && rendered[2].contains(&login.did));
        assert!(
            rendered[4].contains('1'),
            "the store should show its count: {}",
            rendered[4]
        );
        Ok(())
    }

    /// **`Discard` stores nothing.** It is the session store for a login that
    /// only wants the identity: `put` succeeds, every read is empty, and no
    /// conditional write or delete ever reports a row.
    #[tokio::test]
    async fn discard_stores_nothing_and_reports_nothing() -> anyhow::Result<()> {
        let store = Discard;
        let session = a_session();
        store.put(&session).await?;
        assert_eq!(store.get(&session.sub).await?, None);
        assert!(store.get_versioned(&session.sub).await?.is_none());
        assert!(!store.update_if_unchanged(&session, &()).await?);
        assert!(!store.delete(&session.sub).await?);
        assert!(!store.delete_if_unchanged(&session.sub, &()).await?);
        Ok(())
    }

    /// A memory store's version is only meaningful for the store that issued
    /// it: a version read from one store does not authorize a write to another
    /// store's row, even for the same subject at the same write count.
    #[tokio::test]
    async fn a_version_from_one_memory_store_does_not_authorize_a_write_in_another(
    ) -> anyhow::Result<()> {
        let (a, b) = (MemorySessions::new(), MemorySessions::new());
        let session = a_session();
        a.put(&session).await?;
        b.put(&session).await?;
        let (_, from_a) = a.get_versioned(&session.sub).await?.unwrap();
        assert!(!b.delete_if_unchanged(&session.sub, &from_a).await?);
        assert!(!b.update_if_unchanged(&session, &from_a).await?);
        assert!(b.get(&session.sub).await?.is_some());
        Ok(())
    }

    /// Every future the seam returns is `Send`, so a caller can spawn it on a
    /// multi-threaded runtime. Compile-time: nothing here is awaited.
    #[test]
    fn the_session_and_pending_seams_and_their_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        // Generic code is type-checked whatever the argument, so `None` still
        // checks the conditional writes' futures.
        fn sessions<S: SessionStore>(store: &S, session: &Session, version: Option<&S::Version>) {
            assert_send(&store.get("sub"));
            assert_send(&store.get_versioned("sub"));
            assert_send(&store.put(session));
            assert_send(&store.delete("sub"));
            if let Some(version) = version {
                assert_send(&store.update_if_unchanged(session, version));
                assert_send(&store.delete_if_unchanged("sub", version));
            }
        }
        fn pending<P: PendingLoginStore>(store: &P, login: &PendingLogin) {
            assert_send(&store.put(login));
            assert_send(&store.take("state", NOW));
        }
        let session = a_session();
        let memory = MemorySessions::new();
        let login = a_login();
        sessions(&memory, &session, None);
        sessions(&Discard, &session, Some(&()));
        pending(&MemoryPendingLogins::new(), &login);
        assert_send(&memory);
    }

    /// Every future the seam returns is `Send`, so a caller can spawn it on a
    /// multi-threaded runtime. Compile-time: nothing here is awaited.
    #[test]
    fn the_nonce_store_seam_and_its_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn generic<N: NonceStore>(nonces: &N) {
            assert_send(&nonces.get("https://a.example"));
            assert_send(&nonces.put("https://a.example", "n", NOW));
        }
        let nonces = MemoryNonces::new();
        generic(&nonces);
        assert_send(&nonces);
    }
}
