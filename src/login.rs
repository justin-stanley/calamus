//! Logging in: resolve the account, push the authorization request, and turn
//! the callback into a verified identity and a session.
//!
//! [`Client::start`] resolves whatever the user typed, discovers the account's
//! authorization server, pushes PAR (PKCE, DPoP, `private_key_jwt`) and stores
//! a [`PendingLogin`]. [`Client::complete`] consumes that login from the
//! callback, re-discovers the server (the mix-up check), exchanges the code,
//! **refuses tokens whose `sub` is not the DID the login was started for**, and
//! only then stores the [`Session`]. With [`crate::store::Discard`] as the
//! session store this is the identity-only flow ("sign in with atproto"): the
//! `sub` is verified and the tokens are handed back once, not kept.
//!
//! The browser half stays with the caller: setting [`StartedLogin::binding_token`]
//! as a cookie, redirecting to [`StartedLogin::authorize_url`], parsing the
//! callback into [`CallbackParams`], and presenting the cookie back.
//!
//! Every decision is made inside `start_with` and `complete_with`, which take
//! the three network calls as closures, and the closures receive fully-formed
//! requests; [`Client::start`] and [`Client::complete`] only supply the real
//! transports. That is what lets the tests see each decision.
//!
//! Ported from FeatherReader `src/oauth/login.rs`, over the store traits and
//! [`ClientMetadata`] instead of SQLite and `OauthRuntime`.

use std::future::Future;
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};

use crate::client_auth::{self, AuthMethod};
use crate::discovery::{self, AuthorizationServer};
use crate::dpop;
use crate::flow::{self, CallbackParams};
use crate::keys::SigningKey;
use crate::metadata::ClientMetadata;
use crate::net::Fetcher;
use crate::request::{self, PostOutcome, Retry};
use crate::resolve::{self, DnsResolver, ResolvedAccount};
use crate::session::RefreshLocks;
use crate::store::{NonceStore, PendingLogin, PendingLoginStore, Session, SessionStore};
use crate::token;

/// Longest a pending login may sit before it is swept.
///
/// Ten minutes, or the PAR request_uri's own lifetime if shorter. The row holds
/// a DPoP key and a PKCE verifier; keeping it past the point the `request_uri`
/// is usable protects nothing and widens the window in which a stolen `state`
/// is worth replaying.
pub const MAX_PENDING_SECS: i64 = 600;

/// What `Debug` prints in place of a secret.
const REDACTED: &str = "<redacted>";

/// An atproto OAuth client: its identity, its key, and the state every login
/// and refresh shares.
///
/// Build one at startup and share it. [`Client::locks`] serializes refreshes
/// per subject only if every caller uses the same map.
///
/// FeatherReader's `OauthRuntime` without its at-rest codec (storage is the
/// caller's) or its DNS resolver (passed per call in [`Deps`]).
pub struct Client {
    metadata: ClientMetadata,
    /// From `metadata`, precomputed: what is sent must be what is published.
    client_id: String,
    /// The confidential client's ES256 signing key; `None` for the localhost
    /// development client, which is public.
    key: Option<SigningKey>,
    /// From `metadata`, so the method used is the method published.
    auth_method: AuthMethod,
    plc_directory: String,
    locks: RefreshLocks,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("client_id", &self.client_id)
            .field("auth_method", &self.auth_method)
            .field("key_kid", &self.key.as_ref().map(SigningKey::kid))
            .field("plc_directory", &self.plc_directory)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client presenting `metadata`, signing with `key`, resolving `did:plc`
    /// identities at `plc_directory` (normally `https://plc.directory`).
    ///
    /// `client_id` and the authentication method are taken from `metadata`, so
    /// they cannot disagree with the published document. Refuses a confidential
    /// client without its key (it could not sign a client assertion), and a
    /// localhost development client with one (it is public; the key would
    /// never be used or published), and a key that an inline JWKS
    /// ([`Jwks::Inline`](crate::metadata::Jwks::Inline)) does not publish under
    /// its `kid` (no server could verify its assertions).
    pub fn new(
        metadata: ClientMetadata,
        key: Option<SigningKey>,
        plc_directory: impl Into<String>,
    ) -> Result<Self> {
        let auth_method = metadata.auth_method();
        match (auth_method, &key) {
            (AuthMethod::PrivateKeyJwt, None) => bail!(
                "a confidential client authenticates with private_key_jwt and needs its \
                 signing key"
            ),
            (AuthMethod::None, Some(_)) => {
                bail!("the localhost development client is public and takes no signing key")
            }
            _ => {}
        }
        if let (Some(jwks), Some(key)) = (metadata.inline_jwks(), &key) {
            require_published(jwks, key)?;
        }
        Ok(Self {
            client_id: metadata.client_id().to_string(),
            metadata,
            key,
            auth_method,
            plc_directory: plc_directory.into(),
            locks: RefreshLocks::default(),
        })
    }

    /// The client-metadata document this client presents.
    pub fn metadata(&self) -> &ClientMetadata {
        &self.metadata
    }

    /// This client's `client_id`.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The client signing key, for a confidential client.
    pub fn key(&self) -> Option<&SigningKey> {
        self.key.as_ref()
    }

    /// How this client authenticates to authorization servers.
    pub fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }

    /// The PLC directory `did:plc` identities are resolved at.
    pub fn plc_directory(&self) -> &str {
        &self.plc_directory
    }

    /// The per-subject refresh locks, for [`crate::session::valid_session`].
    pub fn locks(&self) -> &RefreshLocks {
        &self.locks
    }

    /// Begin a login for whatever the user typed (a handle or a DID).
    ///
    /// The identity is resolved **before** anything is pushed to an
    /// authorization server, because the PDS we discover from is the one the
    /// resolved DID names. Starting from a handle and trusting a server to tell
    /// us whose it is would be the whole attack.
    ///
    /// `deps.sessions` is not used here. `now` is Unix seconds.
    pub async fn start<D, P, S, N>(
        &self,
        deps: &Deps<'_, D, P, S, N>,
        subject: &str,
        now: i64,
    ) -> Result<StartedLogin>
    where
        D: DnsResolver,
        P: PendingLoginStore,
        N: NonceStore,
    {
        let Deps {
            fetcher,
            dns,
            pending,
            nonces,
            ..
        } = *deps;
        start_with(
            self,
            pending,
            subject,
            now,
            |subject| async move {
                resolve::resolve(dns, fetcher, &subject, &self.plc_directory).await
            },
            |pds_url, auth_method, expected_issuer| async move {
                discovery::discover(fetcher, &pds_url, auth_method, expected_issuer.as_deref())
                    .await
            },
            |req: ParPost| async move {
                post_form(fetcher, nonces, &req.url, &req.key, &req.params, req.retry, req.clock)
                    .await
                    .map(|(outcome, _minted_at)| outcome)
            },
        )
        .await
    }

    /// Finish a login from the callback's query parameters and the
    /// browser-binding cookie it presented.
    ///
    /// The session is stored (`deps.sessions.put`) after the token response's
    /// `sub` is checked against the login's DID and before this returns, so by
    /// the time the caller mints its own cookie the tokens are durable. The
    /// reverse would leave a browser holding a session the server cannot
    /// serve. `now` is Unix seconds.
    pub async fn complete<D, P, S, N>(
        &self,
        deps: &Deps<'_, D, P, S, N>,
        params: &CallbackParams,
        presented_cookie: Option<&str>,
        now: i64,
    ) -> Result<CompletedLogin>
    where
        D: DnsResolver,
        P: PendingLoginStore,
        S: SessionStore,
        N: NonceStore,
    {
        let Deps {
            fetcher,
            dns,
            pending,
            sessions,
            nonces,
        } = *deps;
        complete_with(
            self,
            pending,
            sessions,
            params,
            presented_cookie,
            now,
            // **These three closures must contain NO decisions.** A review of
            // FeatherReader found the first cut had put `Some(&expected_issuer)`
            // and the DPoP key reconstruction in here — outside the seam the
            // tests drive — so both could be broken with the whole suite green.
            // Changing the issuer argument to `None` disabled the
            // authorization-server mix-up defence for every real login and 702
            // tests still passed.
            //
            // Everything decided is decided in `complete_with` and arrives fully
            // formed; these are transports.
            |req: Discovery| async move {
                discovery::discover(
                    fetcher,
                    &req.pds_url,
                    req.auth_method.as_str(),
                    req.expected_issuer.as_deref(),
                )
                .await
            },
            |req: TokenPost| async move {
                post_form(fetcher, nonces, &req.url, &req.key, &req.params, req.retry, req.clock)
                    .await
            },
            |did: String| async move {
                resolve::resolve(dns, fetcher, &did, &self.plc_directory).await
            },
        )
        .await
    }
}

/// What [`Client::start`] and [`Client::complete`] reach the world through.
///
/// `start` uses all but `sessions`; `complete` uses all of them. Use
/// [`crate::store::Discard`] as `sessions` to keep no tokens.
pub struct Deps<'a, D, P, S, N> {
    /// The SSRF-guarded fetcher every request goes through.
    pub fetcher: &'a Fetcher,
    /// Handle → DID by DNS TXT record.
    pub dns: &'a D,
    /// Logins between PAR and the callback.
    pub pending: &'a P,
    /// Where a completed login's session is stored.
    pub sessions: &'a S,
    /// DPoP nonces per server origin.
    pub nonces: &'a N,
}

impl<D, P, S, N> Clone for Deps<'_, D, P, S, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D, P, S, N> Copy for Deps<'_, D, P, S, N> {}

/// A login that has been pushed to the authorization server and is waiting for
/// the user.
///
/// `Debug` prints the authorization endpoint without its query (which carries
/// the one-time `request_uri`) and never the binding token.
pub struct StartedLogin {
    /// Where to send the browser.
    pub authorize_url: String,
    /// The browser-binding token. Set it as a cookie; the callback must present
    /// it or the flow is refused. This is what stops a login CSRF: `state`
    /// alone lives in a server-global table and says nothing about *which*
    /// browser started the flow.
    pub binding_token: String,
}

impl std::fmt::Debug for StartedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let endpoint = self.authorize_url.split('?').next().unwrap_or_default();
        f.debug_struct("StartedLogin")
            .field("authorize_endpoint", &endpoint)
            .field("binding_token", &REDACTED)
            .finish_non_exhaustive()
    }
}

/// Who logged in, and the session the login granted.
///
/// `Debug` carries the DID, the handle and the session's own redacted `Debug`:
/// no token or key is printed.
#[derive(Debug)]
pub struct CompletedLogin {
    /// The account's DID, verified against the token response's `sub`.
    pub did: String,
    /// Only present when it round-tripped: a handle that cannot be verified
    /// back to this DID is not displayed beside the account.
    pub handle: Option<String>,
    /// The session, as stored. With [`crate::store::Discard`] this is the only
    /// copy: revoke it ([`crate::revoke::revoke_tokens`]) if the grant is not
    /// wanted, then drop it.
    pub session: Session,
}

/// What `start_with` hands its PAR transport: a fully-formed request.
///
/// Mirrors [`TokenPost`] deliberately, and for the same reason it exists — a
/// transport that receives ingredients instead of a request lets the decision
/// be wrong where no test can see it.
struct ParPost {
    url: String,
    params: Vec<(&'static str, String)>,
    /// The ACTUAL key the push is signed under, so a test can compare its
    /// thumbprint against the one the pending row stores. Passing a JWK string
    /// and re-parsing it inside the adapter would let a freshly generated key
    /// be accepted — the authorization server binds `request_uri` to this
    /// key's thumbprint, so a different one stored means every login fails at
    /// the token endpoint with a binding error nothing explains.
    key: Arc<SigningKey>,
    retry: Retry,
    /// The login's clock, for the request's DPoP proofs: the transport mints
    /// on it rather than re-anchoring at a truncated second.
    clock: crate::Elapsing,
}

/// [`Client::start`] with its three network boundaries injected.
///
/// **Nothing drove `start` at all** in FeatherReader until this seam existed.
/// Every guard in `complete` had a test and the whole callback got one; this
/// half had neither, because it needs handle resolution, discovery and a PAR
/// endpoint, all over the network. Five decisions made here were therefore
/// unfalsifiable, and each is a silent production failure rather than a loud
/// one:
///
/// - `client_id` — PAR pushed under a foreign client identity
/// - `code_challenge` — derived from a different verifier than the one stored,
///   so PKCE fails at the exchange
/// - the assertion's audience — RFC 7523 requires the issuer, not the PDS
/// - `browser_binding_hash` — hashing a token other than the one returned
///   defeats the login-CSRF binding
/// - `dpop_key_jwk` — storing a key other than the one PAR was signed under
///
/// **Every decision lives here, not in the caller's closures**: arguments
/// assembled inside an adapter are invisible to a test, so they can be wrong
/// with the suite green. The transports receive fully-formed values.
///
/// The assertion and the pending row's expiry use the time at that point
/// (`now` plus what resolution and discovery took), not the entry `now`.
#[allow(clippy::too_many_arguments)]
async fn start_with<R, RFut, D, DFut, P, PFut>(
    client: &Client,
    pending_store: &impl PendingLoginStore,
    subject: &str,
    now: i64,
    resolve: R,
    discover: D,
    push: P,
) -> Result<StartedLogin>
where
    R: FnOnce(String) -> RFut,
    RFut: Future<Output = Result<ResolvedAccount>>,
    D: FnOnce(String, &'static str, Option<String>) -> DFut,
    DFut: Future<Output = Result<AuthorizationServer>>,
    P: FnOnce(ParPost) -> PFut,
    PFut: Future<Output = Result<PostOutcome>>,
{
    let clock = crate::Elapsing::from(now);
    let account = resolve(subject.to_string())
        .await
        .with_context(|| format!("resolving {subject:?}"))?;

    // No prior issuer: this IS the login that establishes one. Passed
    // explicitly so the `None` is visible to a test rather than buried in an
    // adapter — the mix-up re-check on the callback side is armed by the
    // mirror-image argument, and that one was wrong in review.
    let server = discover(account.pds_url.clone(), client.auth_method.as_str(), None)
        .await
        .with_context(|| {
            format!(
                "discovering the authorization server for {}",
                account.pds_url
            )
        })?;

    // Generated BEFORE the push: the authorization server binds the request_uri
    // to this key's thumbprint, and every later call on this grant must use the
    // same key.
    let session_key = SigningKey::generate("session");
    let verifier = flow::new_pkce_verifier();
    let state = flow::new_state();
    let binding_token = flow::new_binding_token();
    let redirect_uri = client.metadata.redirect_uri();
    let scope = client.metadata.scope();

    let mut params = flow::par_params(&flow::ParRequest {
        redirect_uri,
        scope,
        state: &state,
        code_challenge: &flow::pkce_challenge(&verifier),
        login_hint: Some(subject),
    });
    let assertion = client_assertion(client, client.auth_method, &server.issuer, clock.now())?;
    params.extend(client_auth::credential_params(
        client.auth_method,
        &client.client_id,
        assertion.as_deref(),
    )?);
    let (sent_method, sent_type) = {
        let e = client_auth::evidence(&params);
        (e.method, e.assertion_type.map(str::to_owned))
    };

    // `Arc` so the transport can be handed the real key rather than a recipe
    // for one, while the pending row below still stores from the same value.
    let session_key = Arc::new(session_key);
    let outcome = push(ParPost {
        url: server.par_endpoint.clone(),
        params,
        key: Arc::clone(&session_key),
        // PAR is safe to repeat: a rejected attempt consumes nothing.
        retry: Retry::Allowed,
        clock,
    })
    .await?;
    client_auth::log_evidence(
        "par",
        client_auth::ClientAuthEvidence {
            method: sent_method,
            assertion_type: sent_type.as_deref(),
        },
        &server.par_endpoint,
        outcome.status,
    );
    let par = accept_par_response(&outcome)?;

    pending_store
        .put(&PendingLogin {
            state: state.clone(),
            browser_binding_hash: flow::binding_hash(&binding_token),
            pkce_verifier: verifier,
            dpop_key_jwk: session_key.to_jwk_json()?,
            issuer: server.issuer.clone(),
            pds_url: account.pds_url.clone(),
            did: account.did.clone(),
            auth_method: client.auth_method,
            auth_kid: client.key.as_ref().map(|k| k.kid().to_string()),
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            requested_scope: scope.to_string(),
            request_uri: par.request_uri.clone(),
            app_return_to: None,
            expires_at: pending_expiry(clock.now(), par.expires_in),
        })
        .await?;

    Ok(StartedLogin {
        authorize_url: flow::authorize_url(
            &server.authorization_endpoint,
            &client.client_id,
            &par.request_uri,
        )?,
        binding_token,
    })
}

/// What `complete_with` hands its discovery transport. Every field is already
/// decided; the transport only performs the call.
struct Discovery {
    pds_url: String,
    auth_method: AuthMethod,
    /// `Some(issuer)` arms the authorization-server mix-up re-check inside
    /// `discovery::discover`. **The `Option` is constructed here, not in the
    /// adapter**, so a test can see whether the defence is armed at all.
    expected_issuer: Option<String>,
}

/// What `complete_with` hands its token transport.
struct TokenPost {
    url: String,
    params: Vec<(&'static str, String)>,
    /// The ACTUAL key, not a recipe for one. FeatherReader's first cut passed
    /// the JWK string and let the adapter re-parse it, which meant a freshly
    /// generated key would have been accepted — signing the grant under a
    /// thumbprint it was never bound to — with a green suite.
    key: Arc<SigningKey>,
    retry: Retry,
    /// The login's clock, for the request's DPoP proofs.
    clock: crate::Elapsing,
}

/// [`Client::complete`] with the three network boundaries injected.
///
/// **The SEQUENCING is the thing worth testing.** Each guard here has its own
/// unit test, but the value of the mix-up defence is entirely in the ORDER:
/// the issuer re-check must happen BEFORE the code, the PKCE verifier and a
/// `private_key_jwt` assertion are posted anywhere. Injecting the three calls
/// is what makes the order observable.
///
/// **Every decision lives here, not in the caller's closures.** The
/// `Some(issuer)` that arms the mix-up re-check and the DPoP key the grant is
/// bound to were once both assembled inside the adapters, where no test could
/// see them. The transports receive fully-formed arguments.
///
/// Same shape as [`discovery::discover_with`], and for the same reason.
#[allow(clippy::too_many_arguments)]
async fn complete_with<D, DFut, P, PFut, R, RFut>(
    client: &Client,
    pending_store: &impl PendingLoginStore,
    sessions: &impl SessionStore,
    params: &CallbackParams,
    presented_cookie: Option<&str>,
    now: i64,
    discover: D,
    post: P,
    resolve_handle: R,
) -> Result<CompletedLogin>
where
    D: Fn(Discovery) -> DFut,
    DFut: Future<Output = Result<AuthorizationServer>>,
    P: Fn(TokenPost) -> PFut,
    // The outcome, and when the proof that got it was minted.
    PFut: Future<Output = Result<(PostOutcome, i64)>>,
    R: Fn(String) -> RFut,
    RFut: Future<Output = Result<ResolvedAccount>>,
{
    let clock = crate::Elapsing::from(now);
    // Consumes the pending row, checks the browser binding, and validates `iss`
    // — all three, or no code comes back.
    let (pending, code) =
        flow::complete_callback(pending_store, params, presented_cookie, now).await?;

    // **Parsed HERE, before discovery and the exchange.** A DPoP key that will
    // not parse must stop the login before the authorization code is sent
    // anywhere, not after — the final outcome is a failed login either way, so
    // only the absence of a POST distinguishes them.
    //
    // The key is then handed to the token transport by reference, so nothing
    // downstream can substitute a different one: the grant is bound to this
    // thumbprint and no other.
    let key = Arc::new(
        SigningKey::from_jwk_json(&pending.dpop_key_jwk, "session")
            .context("unsealing the login's DPoP key")?,
    );

    // The method the login was STARTED under, not whatever is configured now.
    // A deploy that flipped dev/production between the push and the callback
    // would otherwise present credentials that do not match the ones PAR was
    // authenticated with, and the exchange would fail for a reason nothing in
    // the logs would explain.
    let auth_method = pending.auth_method;

    // The client's IDENTITY must also be the one PAR was pushed under: both
    // its `client_id` and its redirect, which in calamus are independent (in
    // FeatherReader both derive from one public URL, so the redirect alone
    // said it). Without this the exchange presents the code, the PKCE verifier
    // and an assertion as a client the grant was never issued to; it fails at
    // the authorization server, and nothing on our side says why. Checked
    // here, before discovery and any POST, so the reason is in the log rather
    // than inferred from a 400.
    let current_redirect = client.metadata.redirect_uri();
    if current_redirect != pending.redirect_uri {
        bail!(
            "this login was started under a different public URL (redirect {:?}, now {:?}); \
             the client identity changed mid-flight and the exchange would be rejected",
            pending.redirect_uri,
            current_redirect
        );
    }

    // After the redirect: when both changed (a new public URL), the redirect
    // names the configuration change most directly.
    if client.client_id != pending.client_id {
        bail!(
            "this login was started under a different client_id ({:?}, now {:?}); the \
             client identity changed mid-flight and the exchange would be rejected",
            pending.client_id,
            client.client_id
        );
    }

    // **The re-discovered issuer must be the one PAR was pushed under.**
    //
    // Discovery runs again here, from the network, and the token endpoint comes
    // out of THAT document. Every discovery check is internally consistent — a
    // hostile pair of documents satisfies all of them — so nothing else notices
    // if the PDS's protected-resource document was repointed at a different
    // authorization server between the push and this callback.
    //
    // `verify_callback` does not catch it either: the callback legitimately
    // carries the ORIGINAL issuer, because the real server is what the user
    // approved at. Without this check the authorization code, the PKCE verifier
    // and a `private_key_jwt` assertion all go to the new endpoint.
    let server = discover(Discovery {
        pds_url: pending.pds_url.clone(),
        auth_method,
        // `Some`, decided here: this is what arms the mix-up re-check.
        expected_issuer: Some(pending.issuer.clone()),
    })
    .await?;

    let token_params = token_exchange_params(client, &pending, &code, auth_method, clock.now())?;
    let (sent_method, sent_type) = {
        let e = client_auth::evidence(&token_params);
        (e.method, e.assertion_type.map(str::to_owned))
    };

    let (outcome, minted_at) = post(TokenPost {
        url: server.token_endpoint.clone(),
        params: token_params,
        key: Arc::clone(&key),
        // A nonce challenge is rejected BEFORE the grant is processed, so the
        // code is not consumed and the request is safe to resend. The nonce
        // harvested at PAR is routinely stale by now — approval can take minutes
        // and a server nonce lasts at most five.
        retry: Retry::Allowed,
        clock,
    })
    .await?;
    client_auth::log_evidence(
        "token",
        client_auth::ClientAuthEvidence {
            method: sent_method,
            assertion_type: sent_type.as_deref(),
        },
        &server.token_endpoint,
        outcome.status,
    );

    // The `sub` check, then the store. The expiry counts from when the proof
    // that got this response was minted, before the request went out: the
    // server issued the token no earlier, so the stored expiry errs early (a
    // refresh a little soon), never late. As `apply_refresh` does.
    let session = accept_token_response(sessions, &pending, &outcome, minted_at).await?;
    let did = session.sub.clone();

    // The handle is resolved from the DID rather than remembered from the login
    // form: what the user typed is not evidence, and `resolve` returns `None`
    // unless it round-trips. A failure here must not fail the login — the
    // account is already authenticated, and the handle is a display detail.
    let handle = match resolve_handle(did.clone()).await {
        Ok(account) => account.handle,
        Err(err) => {
            tracing::warn!(%err, did = %did, "could not resolve a handle for the new session");
            None
        }
    };

    Ok(CompletedLogin {
        did,
        handle,
        session,
    })
}

/// When a pending login must be swept, capped at [`MAX_PENDING_SECS`].
///
/// **The cap is ours, not the server's.** Without `.min(...)` the authorization
/// server chooses how long a row holding a DPoP key and a PKCE verifier
/// survives, and a server answering with a large `expires_in` widens the window
/// in which a stolen `state` is worth replaying.
fn pending_expiry(now: i64, par_expires_in: i64) -> i64 {
    now.saturating_add(par_expires_in.min(MAX_PENDING_SECS))
}

/// Refuse a signing key that an inline JWKS does not publish: no member with
/// the key's RFC 7638 thumbprint under the key's `kid`.
///
/// The authorization server picks the verification key by the assertion's
/// `kid` and verifies against the published one, so a key published under
/// another `kid` (or not at all) signs assertions that every login and refresh
/// would fail on, at the server. A `jwks_uri` is fetched by the server and is
/// not checked here.
fn require_published(jwks: &serde_json::Value, key: &SigningKey) -> Result<()> {
    let thumbprint = key.thumbprint()?;
    let published = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .any(|member| {
            member.get("kid").and_then(serde_json::Value::as_str) == Some(key.kid())
                && SigningKey::public_thumbprint_of(&member.to_string())
                    .ok()
                    .as_deref()
                    == Some(thumbprint.as_str())
        });
    if !published {
        bail!(
            "the inline JWKS does not publish the client signing key (kid {:?}, thumbprint \
             {thumbprint}): authorization servers could not verify its assertions",
            key.kid()
        );
    }
    Ok(())
}

/// Read a PAR response, refusing a non-2xx before parsing it.
///
/// **Split out so the status check is reachable.** Deleting it let a FAILED push
/// fall through to `parse_par_response`, and a failure body that happened to
/// carry a `request_uri` would then be used to build an authorize URL — sending
/// the user to a grant the server never issued.
fn accept_par_response(outcome: &PostOutcome) -> Result<flow::ParResponse> {
    if !outcome.is_success() {
        bail!(
            "the pushed authorization request failed with status {}",
            outcome.status
        );
    }
    flow::parse_par_response(&outcome.json()?)
}

/// Assemble the token-endpoint form for this pending login.
///
/// **Every value here has to come from the PENDING ROW** rather than from
/// current configuration or a fresh computation: the code, the redirect and
/// the PKCE verifier are all bound by the authorization server to the request
/// that PAR pushed. Substituting any of them — which a refactor can do
/// silently, since all three are plain strings — either breaks every login or,
/// in the PKCE case, removes the proof that the party redeeming the code is the
/// one that requested it.
fn token_exchange_params(
    client: &Client,
    pending: &PendingLogin,
    code: &str,
    auth_method: AuthMethod,
    now: i64,
) -> Result<Vec<(&'static str, String)>> {
    let mut params =
        token::token_request_params(code, &pending.redirect_uri, &pending.pkce_verifier);
    let assertion = client_assertion(client, auth_method, &pending.issuer, now)?;
    params.extend(client_auth::credential_params(
        auth_method,
        &client.client_id,
        assertion.as_deref(),
    )?);
    Ok(params)
}

/// Validate a token-endpoint response, and store the session it grants only if
/// its subject is the DID the login was started for. Returns that session.
///
/// **Split out of `complete` so these checks are reachable without a live
/// authorization server.** The body is parsed only after the status check — a
/// failed exchange must not have its body examined or echoed.
///
/// `now` is what `expires_in` counts from: the time the token request's proof
/// was minted, as for [`crate::session::apply_refresh`].
async fn accept_token_response(
    sessions: &impl SessionStore,
    pending: &PendingLogin,
    outcome: &PostOutcome,
    now: i64,
) -> Result<Session> {
    if !outcome.is_success() {
        bail!("the token exchange failed with status {}", outcome.status);
    }
    let tokens = token::parse_token_response(&outcome.json()?)?;

    // The token's subject must be the DID we resolved and pushed. A server that
    // returns a different one has authorized a different account than the user
    // asked for, and everything downstream is keyed on `sub`.
    if tokens.sub != pending.did {
        bail!(
            "the authorization server returned tokens for a different subject than the \
             login was started for"
        );
    }

    let session = Session {
        sub: tokens.sub,
        issuer: pending.issuer.clone(),
        aud: pending.pds_url.clone(),
        dpop_key_jwk: pending.dpop_key_jwk.clone(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token.unwrap_or_default(),
        token_type: tokens.token_type,
        granted_scope: tokens.granted_scope,
        expires_at: tokens.expires_in.map(|secs| now.saturating_add(secs)),
    };
    sessions.put(&session).await?;
    Ok(session)
}

/// Mint a client assertion when the negotiated method needs one.
fn client_assertion(
    client: &Client,
    method: AuthMethod,
    issuer: &str,
    now: i64,
) -> Result<Option<String>> {
    match method {
        AuthMethod::None => Ok(None),
        AuthMethod::PrivateKeyJwt => {
            let key = client
                .key
                .as_ref()
                .context("private_key_jwt is negotiated but no client signing key is loaded")?;
            Ok(Some(client_auth::client_assertion(
                key,
                &client.client_id,
                issuer,
                now,
            )?))
        }
    }
}

/// POST a form to an authorization-server endpoint with a DPoP proof. Also
/// returns when the proof that got the final response was minted.
async fn post_form(
    fetcher: &Fetcher,
    nonces: &impl NonceStore,
    url: &str,
    key: &SigningKey,
    params: &[(&'static str, String)],
    retry: Retry,
    clock: crate::Elapsing,
) -> Result<(PostOutcome, i64)> {
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    request::send_with_dpop_at(
        fetcher,
        nonces,
        &request::DpopRequest {
            endpoint: dpop::Endpoint::AuthorizationServer,
            url,
            key,
            access_token: None,
            body: request::DpopBody::Form(&borrowed),
            retry,
        },
        clock,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metadata::Jwks;
    use crate::store::memory::{MemoryNonces, MemoryPendingLogins, MemorySessions};
    use crate::store::Discard;
    use crate::testing::{spawn_tls, test_host_override, StaticDns, TestResponse};

    const PUSHED_REDIRECT: &str = "https://feather-reader.com/oauth/callback";
    const PENDING_ISSUER: &str = "https://auth.example.com";

    const PENDING_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    /// A well-formed token-endpoint response granting `sub`.
    fn token_body(sub: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": "at-abc",
            "token_type": "DPoP",
            // NARROWED on purpose: the pending row REQUESTS
            // "atproto transition:generic"; the server grants less. Identical
            // values made an assertion here pass whichever field was stored —
            // the same trap as deriving the token endpoint from the issuer.
            "scope": "atproto",
            "sub": sub,
            "expires_in": 3600,
            "refresh_token": "rt-abc",
        })
    }

    fn outcome(status: u16, body: &serde_json::Value) -> PostOutcome {
        PostOutcome {
            status,
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    /// FeatherReader's SQLite pool held both tables; here, one store of each.
    #[derive(Default)]
    struct Stores {
        pending: MemoryPendingLogins,
        sessions: MemorySessions,
    }

    impl Stores {
        /// The seams `Client::start`/`complete` take, over these stores and an
        /// offline resolver.
        fn deps<'a>(
            &'a self,
            fetcher: &'a Fetcher,
            dns: &'a StaticDns,
            nonces: &'a MemoryNonces,
        ) -> Deps<'a, StaticDns, MemoryPendingLogins, MemorySessions, MemoryNonces> {
            Deps {
                fetcher,
                dns,
                pending: &self.pending,
                sessions: &self.sessions,
                nonces,
            }
        }
    }

    async fn empty_stores() -> Stores {
        Stores::default()
    }

    /// **The authorization server must not be able to log the user in as
    /// somebody else.**
    ///
    /// `complete` pushes PAR for a DID it resolved itself, and the token response
    /// carries a `sub`. If the two are allowed to differ, a hostile or buggy
    /// server hands back a working session for an account the user never asked
    /// for — and everything downstream (`put_session`, the cookie, every later
    /// repo call) is keyed on that `sub`, so the whole app then acts as the wrong
    /// identity.
    ///
    /// Deleting this check passed all 664 tests. It had no test because it sits
    /// after a network round trip that a test cannot make: discovery requires
    /// `https` and the SSRF guard forbids loopback, so there is nowhere to point
    /// a stub. Splitting the response handling out of `complete` is what makes it
    /// reachable — the guard is unchanged, it just no longer requires a live
    /// authorization server to observe.
    #[tokio::test]
    async fn tokens_for_a_different_subject_are_refused() {
        let stores = empty_stores().await;
        let pending = pending_auth("unused-hash");

        let hostile = token_body("did:plc:zzzzzzzzzzzzzzzzzzzzzzzz");
        let err = accept_token_response(
            &stores.sessions,
            &pending,
            &outcome(200, &hostile),
            1_700_000_000,
        )
        .await
        .expect_err("a token response for another DID must be refused");

        assert!(
            format!("{err:#}").contains("different subject"),
            "refused, but not by the subject check: {err:#}",
        );
        assert!(
            stores
                .sessions
                .get("did:plc:zzzzzzzzzzzzzzzzzzzzzzzz")
                .await
                .unwrap()
                .is_none(),
            "no session may be stored for a subject the login did not start for",
        );
    }

    /// The matching-subject case must still succeed and persist the session —
    /// otherwise a check that refused every login would satisfy the test above.
    #[tokio::test]
    async fn tokens_for_the_pending_subject_are_accepted_and_stored() {
        let stores = empty_stores().await;
        let pending = pending_auth("unused-hash");

        let did = accept_token_response(
            &stores.sessions,
            &pending,
            &outcome(200, &token_body(PENDING_DID)),
            1_700_000_000,
        )
        .await
        .expect("a token response for the pending DID must be accepted")
        .sub;

        assert_eq!(did, PENDING_DID);
        let stored = stores
            .sessions
            .get(PENDING_DID)
            .await
            .unwrap()
            .expect("the session must be durable before complete() returns");
        assert_eq!(stored.access_token, "at-abc");
        assert_eq!(stored.issuer, PENDING_ISSUER);
    }

    /// **An absurd clock saturates rather than overflowing**, for both the
    /// stored session's expiry and the pending row's.
    #[tokio::test]
    async fn an_absurd_now_saturates_the_login_expiries() {
        let stores = empty_stores().await;
        let pending = pending_auth("unused-hash");
        let session = accept_token_response(
            &stores.sessions,
            &pending,
            &outcome(200, &token_body(PENDING_DID)),
            i64::MAX - 10,
        )
        .await
        .expect("accepted");
        assert_eq!(session.expires_at, Some(i64::MAX));
        assert_eq!(pending_expiry(i64::MAX - 10, 60), i64::MAX);
    }

    /// **A non-2xx token response must not be parsed as a session.**
    ///
    /// The status check is what stops an error body being read as a grant, and
    /// it also keeps the failure body from being examined at all — it may be an
    /// arbitrary proxy or WAF page.
    #[tokio::test]
    async fn a_failed_token_exchange_stores_nothing() {
        let stores = empty_stores().await;
        let pending = pending_auth("unused-hash");

        // A body that WOULD parse as a valid grant for the right DID, behind a
        // failure status: only the status check stands between it and a session.
        let err = accept_token_response(
            &stores.sessions,
            &pending,
            &outcome(400, &token_body(PENDING_DID)),
            1_700_000_000,
        )
        .await
        .expect_err("a 400 must not yield a session");

        assert!(
            format!("{err:#}").contains("failed with status 400"),
            "refused, but not by the status check: {err:#}",
        );
        assert!(
            stores.sessions.get(PENDING_DID).await.unwrap().is_none(),
            "a failed exchange must leave no session behind",
        );
    }

    /// **The PKCE verifier sent must be the pending row's.**
    ///
    /// PKCE is what proves the party redeeming the code is the party that
    /// requested it. The verifier is a plain `String` three fields away from two
    /// other plain `String`s, so substituting it is a one-token edit — and a
    /// mutation replacing it with a literal passed the whole suite, because
    /// nothing ever looked at the form `complete` builds.
    #[test]
    fn the_token_request_carries_the_pending_rows_pkce_verifier_and_redirect() {
        let client = client_at("https://feather-reader.com");
        let pending = pending_auth("unused-hash");

        let params = token_exchange_params(
            &client,
            &pending,
            "the-code",
            client.auth_method(),
            1_700_000_000,
        )
        .expect("building the token request");
        let get = |k: &str| {
            params
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(
            get("code_verifier"),
            Some(pending.pkce_verifier.as_str()),
            "the verifier must come from the pending row; anything else forfeits PKCE",
        );
        assert_eq!(get("code"), Some("the-code"));
        assert_eq!(
            get("redirect_uri"),
            Some(pending.redirect_uri.as_str()),
            "the redirect must be the one PAR was pushed under",
        );
        assert_eq!(get("grant_type"), Some("authorization_code"));
    }

    /// **A failed PAR push must not be parsed as a successful one.**
    ///
    /// Without the status check a failure body falls through to
    /// `parse_par_response`, so an error response that happens to carry a
    /// `request_uri` would be used to build an authorize URL and the user would
    /// be sent to a grant the server never issued. Deleting it passed everything.
    #[test]
    fn a_failed_par_push_is_not_parsed_as_a_grant() {
        // A body that WOULD parse as a valid PAR response, behind a failure
        // status — so only the status check stands between it and an authorize
        // URL.
        let body = serde_json::json!({ "request_uri": "urn:ietf:params:oauth:request_uri:x", "expires_in": 60 });

        assert!(
            accept_par_response(&outcome(200, &body)).is_ok(),
            "the same body at 200 must parse — otherwise this test proves nothing",
        );

        // `match` rather than `expect_err`: that would require `Debug` on
        // `ParResponse`, and a `request_uri` is a one-time grant reference bound
        // to our DPoP key — not something to make printable for a test's sake.
        let err = match accept_par_response(&outcome(400, &body)) {
            Ok(_) => panic!("a 400 must not yield a request_uri"),
            Err(err) => err,
        };
        assert!(
            format!("{err:#}").contains("failed with status 400"),
            "refused, but not by the status check: {err:#}",
        );
    }

    /// **The pending row's lifetime is capped by us, not chosen by the server.**
    ///
    /// The row holds a sealed DPoP key and a PKCE verifier. Dropping the
    /// `.min(MAX_PENDING_SECS)` lets an authorization server answering with a
    /// large `expires_in` decide how long that sits in our database, widening the
    /// window in which a stolen `state` is worth replaying. The mutation passed
    /// the whole suite.
    #[test]
    fn the_pending_row_lifetime_is_capped_regardless_of_the_server() {
        let now = 1_700_000_000;

        // A server asking for a day gets ten minutes.
        assert_eq!(
            pending_expiry(now, 86_400),
            now + MAX_PENDING_SECS,
            "a server must not be able to extend the pending row past our cap",
        );
        // A shorter server lifetime still wins — the cap is a ceiling, not a
        // floor, and pinning the row open past the request_uri's own life would
        // protect nothing.
        assert_eq!(pending_expiry(now, 60), now + 60);
        assert_eq!(
            pending_expiry(now, MAX_PENDING_SECS),
            now + MAX_PENDING_SECS
        );
    }

    /// One DPoP key for the whole test run.
    ///
    /// Deterministic on purpose: a freshly generated key per fixture made it
    /// impossible to assert WHICH key the token request was signed under, and a
    /// review found that gap was live — substituting a generated key in the
    /// transport passed the entire suite while binding the grant to a thumbprint
    /// the `request_uri` was never issued against.
    fn fixture_dpop_jwk() -> &'static str {
        static JWK: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        JWK.get_or_init(|| SigningKey::generate("session").to_jwk_json().unwrap())
    }

    /// The thumbprint every token request in these tests must carry.
    fn fixture_thumbprint() -> String {
        SigningKey::from_jwk_json(fixture_dpop_jwk(), "session")
            .unwrap()
            .thumbprint()
            .unwrap()
    }

    /// A pending login pushed under [`PUSHED_REDIRECT`], as a value.
    fn pending_auth(cookie_hash: &str) -> PendingLogin {
        PendingLogin {
            state: "state-value".into(),
            browser_binding_hash: cookie_hash.into(),
            pkce_verifier: "verifier".into(),
            // A REAL private JWK. `complete` unseals the DPoP key before it
            // compares redirects, so a placeholder here refuses the login one
            // step too early and the identity check never runs — which the
            // assertion below caught rather than tolerated.
            dpop_key_jwk: fixture_dpop_jwk().to_string(),
            issuer: PENDING_ISSUER.into(),
            pds_url: "https://pds.example.com".into(),
            did: PENDING_DID.into(),
            auth_method: AuthMethod::PrivateKeyJwt,
            auth_kid: None,
            client_id: "https://feather-reader.com/oauth/client-metadata.json".into(),
            redirect_uri: PUSHED_REDIRECT.into(),
            requested_scope: "atproto transition:generic".into(),
            request_uri: "urn:x".into(),
            app_return_to: None,
            expires_at: 2_000_000_000,
        }
    }

    /// Stores holding that pending login, for the tests that drive `complete`
    /// end to end.
    async fn pending_login(cookie_hash: &str) -> Stores {
        let stores = empty_stores().await;
        stores
            .pending
            .put(&pending_auth(cookie_hash))
            .await
            .unwrap();
        stores
    }

    /// A client serving `public_url` the way FeatherReader's runtime does: the
    /// metadata document, callback and JWKS under `/oauth/`, and on a loopback
    /// URL atproto's localhost development client (public, no key).
    fn client_at(public_url: &str) -> Client {
        let base = url::Url::parse(public_url).expect("a test public URL");
        let at = |path: &str| base.join(path).expect("a test URL");
        let scope = "atproto transition:generic";
        // **Offline.** PENDING_DID is a real Bluesky DID, so a real PLC
        // directory would make handle resolution in these tests a live internet
        // call. `.invalid` never resolves (RFC 2606).
        let plc = "https://plc.invalid";
        if matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) {
            let metadata =
                ClientMetadata::localhost_dev(at("/oauth/callback"), scope, "FeatherReader")
                    .expect("the dev client metadata");
            return Client::new(metadata, None, plc).expect("the test client must build");
        }
        let metadata = ClientMetadata::confidential(
            at("/oauth/client-metadata.json"),
            vec![at("/oauth/callback")],
            scope,
            "FeatherReader",
            Some(base.clone()),
            Jwks::Uri(at("/oauth/jwks.json")),
        )
        .expect("the confidential client metadata");
        Client::new(
            metadata,
            Some(SigningKey::generate("featherreader-oauth-1")),
            plc,
        )
        .expect("the test client must build")
    }

    // ── `start`: the half that had no test at all ───────────────────────────

    const START_PDS: &str = "https://pds.example.com";
    const START_ISSUER: &str = "https://auth.example.com";

    fn started_account() -> ResolvedAccount {
        ResolvedAccount {
            did: PENDING_DID.into(),
            pds_url: START_PDS.into(),
            handle: Some("alice.example.com".into()),
        }
    }

    fn started_server() -> AuthorizationServer {
        AuthorizationServer {
            issuer: START_ISSUER.into(),
            par_endpoint: format!("{START_ISSUER}/par"),
            authorization_endpoint: format!("{START_ISSUER}/authorize"),
            token_endpoint: format!("{START_ISSUER}/token"),
            revocation_endpoint: None,
        }
    }

    fn par_ok() -> PostOutcome {
        PostOutcome {
            status: 201,
            body: br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#
                .to_vec(),
        }
    }

    /// Drive `start_with` against a CHOSEN authorization server and PAR
    /// response, capturing the request it pushed.
    ///
    /// [`run_start`] is this with a well-behaved counterparty. The adversarial
    /// tests vary the two, because everything `start` consumes after the push
    /// is bytes from a remote party: the tests above prove `start` says the
    /// right things, and these prove it survives being lied to.
    async fn run_start_against(
        client: &Client,
        stores: &Stores,
        now: i64,
        server: AuthorizationServer,
        par: PostOutcome,
    ) -> (
        Result<StartedLogin>,
        std::sync::Arc<std::sync::Mutex<Vec<ParPost>>>,
    ) {
        let pushed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&pushed);
        let r = start_with(
            client,
            &stores.pending,
            "alice.example.com",
            now,
            |_subject| async move { Ok(started_account()) },
            move |_pds, _method, expected| async move {
                // The mirror image of the callback's mix-up re-check: this side
                // must pass `None`, because this IS the login that establishes
                // the issuer. Asserted here so a `Some(..)` cannot creep in.
                assert!(
                    expected.is_none(),
                    "the initial push must not claim a prior issuer, got {expected:?}"
                );
                Ok(server)
            },
            move |req: ParPost| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(req);
                    Ok(par)
                }
            },
        )
        .await;
        (r, pushed)
    }

    /// Drive `start_with` against a well-behaved counterparty.
    async fn run_start(
        client: &Client,
        stores: &Stores,
        now: i64,
    ) -> (
        Result<StartedLogin>,
        std::sync::Arc<std::sync::Mutex<Vec<ParPost>>>,
    ) {
        run_start_against(client, stores, now, started_server(), par_ok()).await
    }

    /// A PAR response with a chosen status and raw body.
    fn par_body(status: u16, body: &str) -> PostOutcome {
        PostOutcome {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    /// The `state` the push carried — the key the pending row is stored under,
    /// so a test can ask whether one exists without knowing it in advance.
    fn pushed_state(captured: &std::sync::Mutex<Vec<ParPost>>) -> String {
        let c = captured.lock().unwrap();
        assert_eq!(c.len(), 1, "PAR must be pushed exactly once");
        param(&c[0].params, "state")
            .expect("state in the push")
            .to_string()
    }

    /// Assert the login failed AND left no pending row behind.
    ///
    /// Both halves matter. A row written for a grant the server never issued
    /// strands a sealed DPoP key and PKCE verifier in the database, and the
    /// error alone does not prove one was not written.
    async fn assert_refused_without_storing(
        stores: &Stores,
        now: i64,
        started: Result<StartedLogin>,
        captured: &std::sync::Mutex<Vec<ParPost>>,
        what: &str,
    ) -> Result<()> {
        assert!(started.is_err(), "{what} must fail the login");
        let state = pushed_state(captured);
        assert!(
            stores.pending.take(&state, now).await?.is_none(),
            "{what} left a pending row behind",
        );
        Ok(())
    }

    fn param<'a>(params: &'a [(&'static str, String)], k: &str) -> Option<&'a str> {
        params
            .iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.as_str())
    }

    /// **The PAR push carries this client's identity, and the pending row is
    /// written from the same values.**
    ///
    /// Five decisions in `start` were unfalsifiable before this test existed —
    /// see `start_with`. Each is silent in production: the login simply fails
    /// later, at the authorization server, for a reason nothing local explains.
    #[tokio::test]
    async fn a_start_pushes_this_clients_identity_and_stores_what_it_pushed() -> Result<()> {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let now = 1_700_000_000;

        let (started, pushed) = run_start(&client, &stores, now).await;
        let started = started?;
        // Copy what the assertions need and DROP the guard: everything below
        // awaits, and holding a `std::sync::MutexGuard` across an await point
        // is a deadlock waiting for a multi-threaded runtime (clippy's
        // `await_holding_lock`, which CI treats as an error).
        let (url, params, pushed_key_jwk, retry_allowed) = {
            let pushed = pushed.lock().unwrap();
            assert_eq!(pushed.len(), 1, "PAR must be pushed exactly once");
            let r = &pushed[0];
            (
                r.url.clone(),
                r.params.clone(),
                r.key.to_jwk_json()?,
                matches!(r.retry, Retry::Allowed),
            )
        };
        let req = &params;

        assert_eq!(url, format!("{START_ISSUER}/par"), "wrong PAR endpoint");
        assert_eq!(
            param(req, "client_id"),
            Some(client.client_id()),
            "PAR was pushed under a client_id that is not ours",
        );
        assert_eq!(
            param(req, "redirect_uri"),
            Some(client.metadata().redirect_uri()),
        );
        assert!(
            retry_allowed,
            "PAR consumes nothing on rejection and must stay retryable",
        );

        // **The client assertion is addressed to the AUTHORIZATION SERVER.**
        //
        // RFC 7523 §3: `aud` is the server the assertion is presented to, and
        // `iss` = `sub` = the client. Pointing `aud` at the PDS instead — the
        // other URL in scope here, one line away in this function — survived
        // every other assertion in this test, because nothing looked inside the
        // JWT. A wrong audience is rejected by the server as an invalid client
        // assertion, so the login fails with nothing local explaining why.
        let assertion = param(req, "client_assertion").expect("a client assertion");
        let claims: serde_json::Value = {
            use base64::Engine as _;
            let payload = assertion.split('.').nth(1).expect("a JWT payload segment");
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .expect("the payload must be base64url"),
            )
            .expect("the payload must be JSON")
        };
        assert_eq!(
            claims["aud"].as_str(),
            Some(START_ISSUER),
            "the client assertion is addressed to the wrong audience: {claims}",
        );
        assert_eq!(
            claims["iss"].as_str(),
            Some(client.client_id()),
            "the client assertion's issuer is not this client",
        );
        assert_eq!(
            claims["sub"].as_str(),
            Some(client.client_id()),
            "the client assertion's subject is not this client",
        );
        assert_eq!(
            claims["iat"].as_i64(),
            Some(now),
            "iat is not the passed now"
        );
        assert!(
            claims["exp"]
                .as_i64()
                .is_some_and(|e| e > now && e <= now + 300),
            "exp must be ahead of iat and short-lived: {claims}",
        );

        // The row `complete` will read back.
        let pending = stores
            .pending
            .take(param(req, "state").expect("state in the push"), now)
            .await?
            .expect("the pending row must exist");

        // **PKCE: the challenge pushed must derive from the verifier stored.**
        // A fresh verifier on either side compiles and fails only at the
        // exchange, with `invalid_grant` and nothing pointing here.
        assert_eq!(
            param(req, "code_challenge"),
            Some(flow::pkce_challenge(&pending.pkce_verifier).as_str()),
            "the pushed PKCE challenge does not match the stored verifier",
        );

        // **DPoP: the key stored must be the key the push was signed under.**
        // The authorization server binds `request_uri` to this thumbprint.
        assert_eq!(
            pending.dpop_key_jwk, pushed_key_jwk,
            "the pending row stores a different DPoP key than PAR was signed under",
        );

        // **Browser binding: the hash stored must be of the token returned.**
        // Hashing anything else leaves the cookie check unable to match, which
        // is a login-CSRF defence that silently never fires.
        assert_eq!(
            pending.browser_binding_hash,
            flow::binding_hash(&started.binding_token),
            "the stored binding hash is not of the token handed to the browser",
        );

        assert_eq!(pending.issuer, START_ISSUER);
        assert_eq!(pending.pds_url, START_PDS);
        assert_eq!(pending.did, PENDING_DID);
        assert_eq!(pending.request_uri, "urn:ietf:params:oauth:request_uri:abc");
        assert_eq!(pending.redirect_uri, client.metadata().redirect_uri());
        assert_eq!(pending.requested_scope, client.metadata().scope());

        // The browser is sent to the discovered endpoint, carrying the
        // request_uri the server just issued.
        assert!(
            started
                .authorize_url
                .starts_with(&format!("{START_ISSUER}/authorize")),
            "authorize_url does not point at the discovered endpoint: {}",
            started.authorize_url,
        );
        assert!(
            started
                .authorize_url
                .contains("urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc")
                || started
                    .authorize_url
                    .contains("request_uri=urn:ietf:params:oauth:request_uri:abc"),
            "authorize_url does not carry the issued request_uri: {}",
            started.authorize_url,
        );
        Ok(())
    }

    /// **A failed PAR push stores nothing.**
    ///
    /// A pending row written before the server accepted would leave a sealed
    /// DPoP key and PKCE verifier for a grant that does not exist, and the
    /// row's expiry is derived from the PAR response.
    #[tokio::test]
    async fn a_rejected_par_push_stores_no_pending_row() -> Result<()> {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&captured);
        let r = start_with(
            &client,
            &stores.pending,
            "alice.example.com",
            1_700_000_000,
            |_s| async move { Ok(started_account()) },
            |_p, _m, _e| async move { Ok(started_server()) },
            move |req: ParPost| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(req);
                    Ok(PostOutcome {
                        status: 400,
                        body: br#"{"error":"invalid_request"}"#.to_vec(),
                    })
                }
            },
        )
        .await;

        assert!(r.is_err(), "a 400 from PAR must fail the login");
        let state = {
            let c = captured.lock().unwrap();
            param(&c[0].params, "state").expect("state").to_string()
        };
        assert!(
            stores.pending.take(&state, 1_700_000_000).await?.is_none(),
            "a rejected push left a pending row behind",
        );
        Ok(())
    }

    // ── `start` against a hostile counterparty ──────────────────────────────
    //
    // Everything `start` consumes after the push is bytes chosen by a remote
    // party. The tests above drive a cooperative server and prove `start` says
    // the right things; these drive a lying one and prove what it refuses.

    /// **A `request_uri` cannot smuggle extra parameters into the authorize
    /// URL.**
    ///
    /// This value is the one place in `start` where a remote party's bytes are
    /// echoed into a URL we hand the user's browser. Built by string formatting
    /// rather than a query serializer, a `request_uri` carrying
    /// `&redirect_uri=…` appends a SECOND `redirect_uri` to the authorization
    /// request — the classic parameter-injection shape, and on this endpoint it
    /// is an attempt to redirect the grant somewhere the client never
    /// registered.
    #[tokio::test]
    async fn a_hostile_request_uri_cannot_smuggle_parameters_into_the_authorize_url() -> Result<()>
    {
        const SMUGGLED: &str =
            "urn:ietf:params:oauth:request_uri:abc&redirect_uri=https://evil.example.com";
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let body = serde_json::json!({ "request_uri": SMUGGLED, "expires_in": 60 });
        let (started, _) = run_start_against(
            &client,
            &stores,
            1_700_000_000,
            started_server(),
            par_body(201, &body.to_string()),
        )
        .await;

        let url = url::Url::parse(&started?.authorize_url)?;
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs.len(),
            2,
            "the authorize URL gained a parameter from the server's bytes: {pairs:?}",
        );
        assert_eq!(
            pairs
                .iter()
                .find(|(k, _)| k == "request_uri")
                .map(|(_, v)| v.as_str()),
            Some(SMUGGLED),
            "the request_uri must survive as ONE opaque value, not be split",
        );
        assert!(
            !pairs.iter().any(|(k, _)| k == "redirect_uri"),
            "a redirect_uri was smuggled into the authorize URL: {pairs:?}",
        );
        Ok(())
    }

    /// **A 2xx that is not a grant stores nothing.**
    ///
    /// `a_rejected_par_push_stores_no_pending_row` covers a 400. A server that
    /// answers 200 with an error body gets PAST the status check and reaches
    /// the parser — a different path, and the one a misbehaving (rather than
    /// refusing) server takes.
    #[tokio::test]
    async fn a_par_success_carrying_no_grant_stores_nothing() -> Result<()> {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let now = 1_700_000_000;
        let (started, captured) = run_start_against(
            &client,
            &stores,
            now,
            started_server(),
            par_body(200, r#"{"error":"invalid_request"}"#),
        )
        .await;
        assert_refused_without_storing(
            &stores,
            now,
            started,
            &captured,
            "a 200 with no request_uri",
        )
        .await
    }

    /// **A body that is not JSON at all stores nothing.**
    ///
    /// An HTML error page from a proxy in front of the authorization server is
    /// the realistic shape here, and it arrives with a 200.
    #[tokio::test]
    async fn a_par_response_that_is_not_json_stores_nothing() -> Result<()> {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let now = 1_700_000_000;
        let (started, captured) = run_start_against(
            &client,
            &stores,
            now,
            started_server(),
            par_body(200, "<html><body>502 Bad Gateway</body></html>"),
        )
        .await;
        assert_refused_without_storing(&stores, now, started, &captured, "a non-JSON PAR body")
            .await
    }

    /// **A non-positive `expires_in` is refused rather than stored.**
    ///
    /// Stored as given, a zero or negative lifetime writes a row that is
    /// already expired — the login cannot be completed and the failure surfaces
    /// at the callback as a missing state, which reads like a browser problem
    /// rather than a server one.
    #[tokio::test]
    async fn a_non_positive_par_lifetime_is_refused_rather_than_stored() -> Result<()> {
        let client = client_at("https://app.example.com");
        let now = 1_700_000_000;
        for expires_in in ["0", "-1"] {
            let stores = empty_stores().await;
            let body = format!(
                r#"{{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":{expires_in}}}"#
            );
            let (started, captured) = run_start_against(
                &client,
                &stores,
                now,
                started_server(),
                par_body(201, &body),
            )
            .await;
            assert_refused_without_storing(
                &stores,
                now,
                started,
                &captured,
                &format!("expires_in={expires_in}"),
            )
            .await?;
        }
        Ok(())
    }

    /// **A server cannot pin a pending login open beyond our own cap.**
    ///
    /// The row holds a sealed DPoP key and PKCE verifier. An authorization
    /// server answering `expires_in: 10^9` would otherwise keep that material
    /// alive for thirty years, and the lifetime of our secrets is not the
    /// counterparty's to choose. `pending_expiry` has a unit test; this is the
    /// one that proves `start` actually routes the server's number through it.
    #[tokio::test]
    async fn a_server_cannot_pin_a_pending_login_beyond_the_cap() -> Result<()> {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let now = 1_700_000_000;
        let (started, captured) = run_start_against(
            &client,
            &stores,
            now,
            started_server(),
            par_body(
                201,
                r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":1000000000}"#,
            ),
        )
        .await;
        started?;

        let state = pushed_state(&captured);
        let pending = stores
            .pending
            .take(&state, now)
            .await?
            .expect("the pending row must exist");
        assert_eq!(
            pending.expires_at,
            now + MAX_PENDING_SECS,
            "the server's lifetime was accepted instead of our cap",
        );
        Ok(())
    }

    /// **A non-https authorization endpoint fails the login.**
    ///
    /// `discovery` already requires https on every endpoint it returns, so this
    /// is the second layer rather than the first — it holds even if a future
    /// change to discovery, or a different path into `start_with`, hands one
    /// through. Downgrading this URL puts the authorization request, and the
    /// user's credentials at the other end of it, on the wire in clear.
    #[tokio::test]
    async fn a_non_https_authorization_endpoint_fails_the_login() -> Result<()> {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let downgraded = AuthorizationServer {
            authorization_endpoint: "http://auth.example.com/authorize".into(),
            ..started_server()
        };
        let (started, _) = run_start_against(
            &client,
            &stores,
            1_700_000_000,
            downgraded,
            par_body(
                201,
                r#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#,
            ),
        )
        .await;
        // Destructured rather than `expect_err`, which would need
        // `StartedLogin: Debug` — and that type holds `binding_token`. It is
        // deliberately not `Debug`, so a panic message can never print it.
        let Err(err) = started else {
            panic!("an http authorization endpoint must fail the login")
        };
        assert!(
            format!("{err:#}").contains("https"),
            "the failure should name the scheme, got: {err:#}",
        );
        Ok(())
    }

    fn callback_params() -> flow::CallbackParams {
        flow::CallbackParams {
            code: Some("the-code".into()),
            state: Some("state-value".into()),
            iss: Some(PENDING_ISSUER.into()),
            error: None,
            error_description: None,
            response: None,
        }
    }

    /// **`complete` — the code exchange — had no test at all, and this is the
    /// first one to actually call it.**
    ///
    /// `login.rs` contained exactly two tests and neither invoked `complete`;
    /// both asserted that `metadata::redirect_uri` is a function of its input,
    /// one of them as the literal tautology `f(x) == f(x)`. Five separate guards
    /// inside `complete` could each be deleted with the whole suite still green,
    /// including the check that the tokens belong to the DID the login started
    /// for. The function is reachable only on the rust backend, so it is dormant
    /// today — the cutover makes it every user's login path.
    ///
    /// This pins the identity check: the pending row was pushed under
    /// `feather-reader.com`, the runtime now serves loopback, and the exchange
    /// must be refused BY THAT CHECK.
    ///
    /// Asserting the specific message matters more than usual here. Discovery
    /// against `pds.example.com` would fail anyway — so `is_err()` alone would
    /// pass with the check deleted, which is exactly how the rest of this module
    /// came to be untested. Matching the message is what makes the mutation
    /// visible.
    #[tokio::test]
    async fn a_login_started_under_a_different_public_url_is_refused() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("http://127.0.0.1:8080");
        let fetcher = Fetcher::default();

        let err = client
            .complete(
                &stores.deps(&fetcher, &StaticDns::new(), &MemoryNonces::new()),
                &callback_params(),
                Some(&cookie),
                1_700_000_000,
            )
            .await
            .expect_err("a client-identity change mid-flight must refuse the exchange");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("started under a different public URL")
                && rendered.contains(PUSHED_REDIRECT),
            "refused, but not BY the client-identity check — this is the failure mode \
             where discovery merely errored instead: {rendered}",
        );
    }

    /// **The identity check must also let a MATCHING login through.**
    ///
    /// A check that refuses everything satisfies the test above, so this pins the
    /// other direction: with the runtime serving the same public URL the row was
    /// pushed under, `complete` must get PAST the redirect comparison and fail
    /// later — at discovery, which cannot reach `pds.example.com` from a test.
    ///
    /// This is deliberately an assertion about WHICH error comes back, not about
    /// success: a full exchange needs a stub authorization server, and the SSRF
    /// guard forbids loopback, so one cannot be reached from here. That is the
    /// same wall that left this function untested, and closing it properly needs
    /// an injectable resolver rather than another test.
    #[tokio::test]
    async fn a_matching_public_url_passes_the_identity_check() {
        let cookie = flow::new_binding_token();
        let stores = empty_stores().await;
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        // **Offline.** FeatherReader pointed this at `pds.example.com` and let
        // real DNS fail; `.invalid` (RFC 2606) fails the same way, at the same
        // step, without asking anyone.
        pending.pds_url = "https://pds.example.invalid".into();
        stores.pending.put(&pending).await.unwrap();
        let client = client_at("https://feather-reader.com");
        let fetcher = Fetcher::default();

        let err = client
            .complete(
                &stores.deps(&fetcher, &StaticDns::new(), &MemoryNonces::new()),
                &callback_params(),
                Some(&cookie),
                1_700_000_000,
            )
            .await
            .expect_err("discovery cannot reach pds.example.invalid from a test");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("oauth-protected-resource") && rendered.contains("resolving host"),
            "the exchange should have got as far as discovery: {rendered}"
        );
        assert!(
            !rendered.contains("started under a different public URL"),
            "a login whose public URL never changed must not be refused as though it \
             had; the identity check is rejecting valid logins: {rendered}",
        );
    }

    // ── END-TO-END: the SEQUENCING, not the individual guards ────────────────
    //
    // Every guard in `complete` has its own unit test. Nothing drove the whole
    // callback, because it needs discovery and a token endpoint over the
    // network — and an issuer must be `https`, so a local plain-HTTP server
    // cannot stand in for an authorization server either. `complete_with`
    // injects those two calls so the ORDER becomes observable.
    //
    // What these assert is mostly what did NOT happen: a guard that fires only
    // after the authorization code has been posted somewhere is not a guard.

    /// Records what the injected boundaries were asked to do — including the
    /// fields a review found were being decided in untested adapter code.
    #[derive(Default)]
    struct Calls {
        /// `(pds_url, expected_issuer, auth_method)`. The `Option` is the point:
        /// `None` means the mix-up re-check was never armed.
        discovered: Vec<(String, Option<String>, String)>,
        posted: Vec<PostedCall>,
        resolved: Vec<String>,
    }
    type Log = std::sync::Arc<std::sync::Mutex<Calls>>;

    /// One recorded token POST: where, with what, under which key, retryable?
    struct PostedCall {
        url: String,
        params: Vec<(&'static str, String)>,
        dpop_thumbprint: String,
        retry: Retry,
    }

    /// The token endpoint a real authorization server would publish: on a
    /// DIFFERENT host and path from the issuer.
    ///
    /// **Deliberately not `{issuer}/token`.** With the endpoints derived from the
    /// issuer string, ignoring the discovery result entirely — posting to
    /// `format!("{}/token", pending.issuer)` — passed all 16 tests. Real servers
    /// do not follow that pattern; this repo's own discovery fixture publishes
    /// `https://pds.justin-stanley.com/oauth/token` against a different issuer.
    const DISCOVERED_TOKEN_ENDPOINT: &str = "https://token.example.net/oauth/v2/token";

    fn server_at(issuer: &str) -> AuthorizationServer {
        AuthorizationServer {
            issuer: issuer.into(),
            par_endpoint: format!("{issuer}/par"),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: DISCOVERED_TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: None,
        }
    }

    /// Drive `complete_with`, recording all three boundaries. Fully OFFLINE:
    /// handle resolution is injected too, so no test here touches the network.
    async fn drive(
        stores: &Stores,
        client: &Client,
        params: &flow::CallbackParams,
        cookie: Option<&str>,
        discovered_issuer: &str,
        token_status: u16,
        token_body: serde_json::Value,
    ) -> (Result<CompletedLogin>, Log) {
        let log: Log = Default::default();
        let (s1, s2, s3) = (
            std::sync::Arc::clone(&log),
            std::sync::Arc::clone(&log),
            std::sync::Arc::clone(&log),
        );
        let issuer = discovered_issuer.to_string();
        let body = serde_json::to_vec(&token_body).unwrap();
        let out = complete_with(
            client,
            &stores.pending,
            &stores.sessions,
            params,
            cookie,
            1_700_000_000,
            move |req| {
                let sink = std::sync::Arc::clone(&s1);
                let issuer = issuer.clone();
                async move {
                    sink.lock().unwrap().discovered.push((
                        req.pds_url,
                        req.expected_issuer,
                        req.auth_method.as_str().to_string(),
                    ));
                    Ok(server_at(&issuer))
                }
            },
            move |req: TokenPost| {
                let sink = std::sync::Arc::clone(&s2);
                let body = body.clone();
                async move {
                    // The thumbprint is what the grant is bound to; recording it
                    // is how a substituted key becomes visible.
                    let tp = req.key.thumbprint().unwrap_or_default();
                    sink.lock().unwrap().posted.push(PostedCall {
                        url: req.url,
                        params: req.params,
                        dpop_thumbprint: tp,
                        retry: req.retry,
                    });
                    let outcome = PostOutcome {
                        status: token_status,
                        body,
                    };
                    Ok((outcome, req.clock.now()))
                }
            },
            move |did| {
                let sink = std::sync::Arc::clone(&s3);
                async move {
                    sink.lock().unwrap().resolved.push(did);
                    // Offline: the handle lookup is allowed to fail, and the
                    // login must survive it.
                    Err(anyhow::anyhow!("handle resolution unavailable in tests"))
                }
            },
        )
        .await;
        (out, log)
    }

    /// **The happy path, start to finish — the first test that drives one.**
    ///
    /// Consumes the pending row, checks the browser binding and `iss`, unseals
    /// the DPoP key, re-discovers, exchanges, and stores a session. The handle
    /// lookup is left to fail (the runtime points at a `.invalid` PLC host, so
    /// it fails offline and fast) which also pins that a handle failure does NOT
    /// fail the login.
    #[tokio::test]
    async fn a_full_callback_stores_a_session() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        let done = out.expect("the full callback should complete");
        assert_eq!(done.did, PENDING_DID);
        assert!(
            done.handle.is_none(),
            "the handle lookup was expected to fail offline"
        );

        // Copied out in a block so the guard is gone before the `await` below;
        // a MutexGuard held across an await is a clippy deny in CI.
        let (
            discoveries,
            expected_issuer,
            auth_method,
            posts,
            token_url,
            thumbprint,
            retry,
            token_params,
        ) = {
            let calls = log.lock().unwrap();
            (
                calls.discovered.len(),
                calls.discovered[0].1.clone(),
                calls.discovered[0].2.clone(),
                calls.posted.len(),
                calls.posted[0].url.clone(),
                calls.posted[0].dpop_thumbprint.clone(),
                calls.posted[0].retry,
                calls.posted[0].params.clone(),
            )
        };
        assert_eq!(discoveries, 1, "discovery ran once");
        assert_eq!(
            auth_method, "private_key_jwt",
            "discovery was told the wrong auth method; `none` would disable the \
             token_endpoint_auth_methods_supported check and the server would \
             then receive a private_key_jwt assertion it never advertised",
        );
        assert_eq!(
            expected_issuer.as_deref(),
            Some(PENDING_ISSUER),
            "the mix-up re-check was not armed: discovery got {expected_issuer:?}",
        );
        assert_eq!(posts, 1, "the token exchange ran once");
        assert_eq!(
            token_url, DISCOVERED_TOKEN_ENDPOINT,
            "the grant went to an endpoint guessed from the issuer rather than \
             the one discovery returned",
        );
        assert_eq!(
            retry,
            Retry::Allowed,
            "the token POST must be retryable: a nonce challenge is rejected \
             before the grant is processed, so the code is not consumed",
        );
        // The grant is bound to the PENDING ROW's DPoP key and no other. A
        // substituted key also has a non-empty thumbprint, so only an equality
        // check catches it.
        // The code from THIS callback is what gets exchanged.
        assert!(
            token_params
                .iter()
                .any(|(k, v)| *k == "code" && v == "the-code"),
            "the token request did not carry the callback's authorization code: {token_params:?}",
        );
        assert_eq!(
            thumbprint,
            fixture_thumbprint(),
            "the token request was signed under a different key than the one the \
             authorization request was bound to",
        );

        // Resolution happens exactly once, and after the exchange.
        //
        // NOT "for the DID the grant returned rather than the pending row" — a
        // review pointed out that claim is unfalsifiable, because
        // `accept_token_response` bails unless `tokens.sub == pending.did`, so
        // the two are provably equal on every path that reaches here. What is
        // left worth asserting is the count and the subject.
        assert_eq!(
            log.lock().unwrap().resolved,
            vec![PENDING_DID.to_string()],
            "the handle lookup did not run exactly once for this subject",
        );
        let stored = stores
            .sessions
            .get(PENDING_DID)
            .await
            .unwrap()
            .expect("no session was stored for a successful login");
        // The caller gets the session it stored (and, with `store::Discard`,
        // the only copy of it).
        assert_eq!(
            done.session, stored,
            "complete returned a different session than it stored"
        );

        // **The session must PERSIST the DPoP key the grant was bound to.**
        //
        // A review found this unpinned even after the EXCHANGE's key was fixed:
        // storing a freshly generated key left 708 tests green. The access token
        // is DPoP-bound to the pending key's thumbprint, so a session holding any
        // other key fails proof validation on every later PDS call — a login that
        // succeeds and then does nothing. That is the worst shape this bug could
        // take, because the failure surfaces far from its cause.
        let stored_thumbprint = SigningKey::from_jwk_json(&stored.dpop_key_jwk, "session")
            .expect("the stored session's DPoP key does not parse")
            .thumbprint()
            .unwrap();
        assert_eq!(
            stored_thumbprint,
            fixture_thumbprint(),
            "the session persisted a different DPoP key than the grant is bound to",
        );

        // **Every remaining field `accept_token_response` writes.**
        //
        // A review found four of the nine unpinned — and the same mapping on the
        // REFRESH path has dedicated tests for each of them. The login half of a
        // mapping tested twice over on the refresh half.
        assert_eq!(stored.access_token, "at-abc");
        assert_eq!(
            stored.refresh_token, "rt-abc",
            "an empty refresh token stores an un-refreshable session: the first \
             refresh presents \"\" and the server's invalid_grant deletes it, \
             which is the spurious logout the token module exists to avoid",
        );
        assert_eq!(stored.token_type, "DPoP");
        assert_eq!(
            stored.granted_scope, "atproto",
            "the session stored the REQUESTED scope, not the granted one — a \
             narrowed grant must be visible now rather than as a mystery write \
             failure later",
        );
        assert_eq!(
            stored.expires_at,
            Some(1_700_000_000 + 3600),
            "the session's expiry is not the token's; `None` means `is_stale` is \
             never true, so it is never proactively refreshed and simply dies",
        );
        assert_eq!(stored.issuer, PENDING_ISSUER);
    }

    /// **A wrong `iss` stops the flow BEFORE anything is posted.**
    ///
    /// RFC 9207. The check itself is unit-tested; what was not pinned is that it
    /// runs early enough to matter. A version that validated `iss` after the
    /// exchange would still "reject the login" while having already handed the
    /// code and a client assertion to the wrong server.
    #[tokio::test]
    async fn a_mismatched_iss_posts_nothing_anywhere() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some("https://evil.example.com".into());

        let (out, log) = drive(
            &stores,
            &client,
            &params,
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "a mismatched iss completed the login");
        let calls = log.lock().unwrap();
        assert!(
            calls.posted.is_empty(),
            "the authorization code was posted despite a bad iss: {:?}",
            calls.posted.iter().map(|p| &p.url).collect::<Vec<_>>(),
        );
        assert!(
            calls.discovered.is_empty(),
            "discovery ran before the iss check",
        );
    }

    /// **The browser binding is checked before anything is posted.**
    ///
    /// A callback replayed from a different browser must not reach the token
    /// endpoint with a valid code.
    #[tokio::test]
    async fn a_foreign_browser_posts_nothing_anywhere() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some("a-different-browser"),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "a foreign browser completed the login");
        let calls = log.lock().unwrap();
        assert!(calls.posted.is_empty());
        assert!(
            calls.discovered.is_empty(),
            "discovery ran before the browser binding was checked",
        );
    }

    /// **Discovery is told which issuer PAR was pushed under.**
    ///
    /// The mix-up defence itself lives INSIDE `discovery::discover` — which this
    /// seam stubs — and is tested there. What belongs at THIS layer is the
    /// contract that makes it reachable: `complete` must hand discovery the
    /// issuer from the *pending row*, which is AAD-bound in storage. Passing
    /// `None`, or the issuer off the callback, would disable the check without
    /// changing a line inside `discover`.
    #[tokio::test]
    async fn discovery_is_given_the_stored_issuer_to_expect() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(out.is_ok());

        let calls = log.lock().unwrap();
        assert_eq!(
            calls.discovered[0].1.as_deref(),
            Some(PENDING_ISSUER),
            "discovery was not told which issuer to expect; the mix-up defence \
             is disabled from the caller's side",
        );
        assert_eq!(
            calls.discovered[0].0, "https://pds.example.com",
            "discovery was pointed at something other than the stored PDS",
        );
    }

    /// **The pending row is consumed: the same callback cannot be replayed.**
    ///
    /// Single-use is what makes a leaked `state` worthless. The second attempt
    /// must fail, and must not reach the token endpoint.
    #[tokio::test]
    async fn a_replayed_callback_is_refused_and_posts_nothing() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let first = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(first.0.is_ok(), "the first callback should succeed");

        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(out.is_err(), "the callback was replayable");
        assert!(
            log.lock().unwrap().posted.is_empty(),
            "a replayed callback still reached the token endpoint",
        );
    }

    /// **A DPoP key that will not unseal posts nothing anywhere.**
    ///
    /// Added because a comment claimed this ordering mattered and no test held
    /// it down: moving the unseal to AFTER the token exchange left the whole
    /// suite green, because every other fixture carries a valid JWK. The final
    /// outcome is identical either way — the login fails — so only the absence
    /// of a POST distinguishes them, and that is the whole point. A corrupt key
    /// must not cost the authorization code a trip to the token endpoint.
    #[tokio::test]
    async fn a_corrupt_dpop_key_posts_nothing_anywhere() {
        let cookie = flow::new_binding_token();
        let stores = empty_stores().await;
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        pending.dpop_key_jwk = "{\"kty\":\"EC\",\"crv\":\"bogus\"}".into();
        stores.pending.put(&pending).await.unwrap();

        let client = client_at("https://feather-reader.com");
        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "a corrupt DPoP key completed the login");
        let calls = log.lock().unwrap();
        assert!(
            calls.posted.is_empty(),
            "the authorization code was posted before the DPoP key was checked",
        );
        assert!(
            calls.discovered.is_empty(),
            "discovery ran before the DPoP key was checked",
        );
    }

    // ── THE ADAPTER, over real TLS ───────────────────────────────────────────
    //
    // Everything above drives `complete_with`, whose transports are stubs — so
    // the wiring in `complete` that hands those transports their arguments has
    // no coverage. A review proved that gap was live: the mix-up defence could
    // be disarmed there with the whole suite green.
    //
    // These drive the REAL `complete`. That needs a server the client will talk
    // to, which needs https (an issuer must be https) on loopback (which the
    // SSRF guard refuses) — hence the test CA in `net`.

    /// Documents for a well-formed PDS + authorization server on one TLS server.
    fn discovery_routes(
        pds: &str,
        issuer: &str,
    ) -> std::collections::HashMap<String, Vec<TestResponse>> {
        let mut r = std::collections::HashMap::new();
        r.insert(
            "/.well-known/oauth-protected-resource".to_string(),
            vec![TestResponse::json(
                200,
                serde_json::json!({
                    "resource": pds,
                    "authorization_servers": [issuer],
                })
                .to_string(),
            )],
        );
        r.insert(
            "/.well-known/oauth-authorization-server".to_string(),
            vec![TestResponse::json(
                200,
                serde_json::json!({
                    "issuer": issuer,
                    "pushed_authorization_request_endpoint": format!("{issuer}/par"),
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                    "protected_resources": [pds],
                    "client_id_metadata_document_supported": true,
                    "require_pushed_authorization_requests": true,
                    "authorization_response_iss_parameter_supported": true,
                    "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
                    "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                    "dpop_signing_alg_values_supported": ["ES256"],
                    "scopes_supported": ["atproto"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                })
                .to_string(),
            )],
        );
        r
    }

    /// Seed a pending login pointing at the live TLS server.
    async fn pending_against(pds: &str, issuer: &str, cookie: &str) -> Stores {
        let stores = empty_stores().await;
        let mut pending = pending_auth(&flow::binding_hash(cookie));
        pending.pds_url = pds.to_string();
        pending.issuer = issuer.to_string();
        stores.pending.put(&pending).await.unwrap();
        stores
    }

    /// **The adapter really forwards the expected issuer — over real TLS.**
    ///
    /// THE test this whole harness exists for. The PDS names an authorization
    /// server that is NOT the one PAR was pushed under; `complete` must refuse
    /// before the authorization code is posted anywhere.
    ///
    /// This is the authorization-server mix-up. It is the one defence whose
    /// value is entirely in WHERE it happens, and the wiring that arms it —
    /// `Some(expected_issuer)` handed to `discover` — sits in `complete`'s
    /// adapter, outside every stub-driven test. Changing it to `None` left 702
    /// tests green. It does not leave this one green.
    #[tokio::test]
    async fn a_repointed_authorization_server_is_refused_before_the_code_is_posted() {
        let cookie = flow::new_binding_token();
        let (addr, log) = spawn_tls(|addr| {
            let port = addr.port();
            // The PDS points at as-EVIL; the pending row was pushed under as-e2e.
            discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-evil.test:{port}"),
            )
        })
        .await;
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test", "as-evil.test"] {
            test_host_override(&fetcher, h, addr);
        }

        let port = addr.port();
        let pds = format!("https://pds-e2e.test:{port}");
        let honest = format!("https://as-e2e.test:{port}");

        let stores = pending_against(&pds, &honest, &cookie).await;
        let client = client_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(honest.clone());

        let err = client
            .complete(
                &stores.deps(&fetcher, &StaticDns::new(), &MemoryNonces::new()),
                &params,
                Some(&cookie),
                1_700_000_000,
            )
            .await
            .expect_err("a repointed authorization server completed the login");

        let rendered = format!("{err:#}");
        // The real message names both servers and says why, which is more than
        // the word "issuer" — assert on the substance, and on BOTH names, so a
        // generic failure (TLS, 404, parse) cannot satisfy this.
        let lower = rendered.to_ascii_lowercase();
        assert!(
            lower.contains("different authorization server")
                && rendered.contains("as-evil.test")
                && rendered.contains("as-e2e.test"),
            "refused, but not by the mix-up check: {rendered}",
        );
        let seen = log.lock().unwrap().join("\n");
        assert!(
            !seen.contains("POST /token"),
            "the authorization code was posted to a server the user never \
             approved:\n{seen}",
        );
    }

    /// **The honest path over the same real TLS server completes.**
    ///
    /// Without this, the test above is satisfied by a `complete` that refuses
    /// everything — including every real login.
    #[tokio::test]
    async fn a_well_formed_discovery_over_tls_reaches_the_token_endpoint() {
        let cookie = flow::new_binding_token();
        let (addr, log) = spawn_tls(|addr| {
            let port = addr.port();
            let pds = format!("https://pds-e2e.test:{port}");
            let issuer = format!("https://as-e2e.test:{port}");
            let mut r = discovery_routes(&pds, &issuer);
            // The exchange itself fails; what is asserted is that it was REACHED.
            r.insert(
                "/token".to_string(),
                vec![TestResponse::json(400, "{\"error\":\"invalid_grant\"}")],
            );
            r
        })
        .await;
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test"] {
            test_host_override(&fetcher, h, addr);
        }

        let port = addr.port();
        let pds = format!("https://pds-e2e.test:{port}");
        let issuer = format!("https://as-e2e.test:{port}");
        let stores = pending_against(&pds, &issuer, &cookie).await;
        let client = client_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(issuer.clone());

        let _ = client
            .complete(
                &stores.deps(&fetcher, &StaticDns::new(), &MemoryNonces::new()),
                &params,
                Some(&cookie),
                1_700_000_000,
            )
            .await;

        let seen = log.lock().unwrap().join("\n");
        assert!(
            seen.contains("/.well-known/oauth-protected-resource"),
            "discovery never fetched the protected-resource document:\n{seen}",
        );
        assert!(
            seen.contains("POST /token"),
            "a well-formed discovery never reached the token endpoint — the \
             refusal test above would pass for the wrong reason:\n{seen}",
        );
    }

    /// The DPoP proof JWT from a recorded request.
    fn dpop_proof(raw: &str) -> String {
        raw.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("dpop:"))
            .expect("no DPoP header on the request")[5..]
            .trim()
            .to_string()
    }

    /// Decode one base64url segment of a JWT as JSON.
    fn jwt_part(jwt: &str, idx: usize) -> serde_json::Value {
        use base64::Engine as _;
        let seg = jwt.split('.').nth(idx).expect("malformed JWT");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(seg)
            .expect("JWT segment is not base64url");
        serde_json::from_slice(&raw).expect("JWT segment is not JSON")
    }

    /// Pull the `jwk` out of a recorded request's DPoP proof header.
    fn dpop_jwk_from(raw: &str) -> String {
        use base64::Engine as _;
        let line = raw
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("dpop:"))
            .expect("no DPoP header on the token request");
        let jwt = line[5..].trim();
        let header_b64 = jwt.split('.').next().expect("malformed DPoP proof");
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("DPoP header is not base64url");
        let v: serde_json::Value = serde_json::from_slice(&json).expect("DPoP header is not JSON");
        v.get("jwk")
            .expect("DPoP header carries no jwk")
            .to_string()
    }

    /// **The grant is signed under the PENDING ROW's key — checked on the wire.**
    ///
    /// The adapter could substitute a freshly generated key and every stub-driven
    /// test stayed green, because the stub is handed the key rather than the
    /// proof. Here the real proof reaches a real server, and its embedded public
    /// key is compared against the key the authorization request was bound to.
    ///
    /// A substituted key also produces a valid-looking proof, so only comparing
    /// thumbprints catches it.
    #[tokio::test]
    async fn the_token_request_is_signed_under_the_pending_rows_key() {
        let cookie = flow::new_binding_token();
        let (addr, log) = spawn_tls(|addr| {
            let port = addr.port();
            let mut r = discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-e2e.test:{port}"),
            );
            r.insert(
                "/token".to_string(),
                vec![TestResponse::json(400, "{\"error\":\"invalid_grant\"}")],
            );
            r
        })
        .await;
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test"] {
            test_host_override(&fetcher, h, addr);
        }
        let port = addr.port();
        let issuer = format!("https://as-e2e.test:{port}");
        let stores =
            pending_against(&format!("https://pds-e2e.test:{port}"), &issuer, &cookie).await;
        let client = client_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(issuer);

        let _ = client
            .complete(
                &stores.deps(&fetcher, &StaticDns::new(), &MemoryNonces::new()),
                &params,
                Some(&cookie),
                1_700_000_000,
            )
            .await;

        let token_req = log
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.starts_with("POST /token"))
            .cloned()
            .expect("the token endpoint was never reached");
        let on_the_wire = SigningKey::public_thumbprint_of(&dpop_jwk_from(&token_req)).unwrap();
        assert_eq!(
            on_the_wire,
            fixture_thumbprint(),
            "the token request was signed under a key the authorization request \
             was never bound to",
        );
    }

    /// **A `use_dpop_nonce` challenge is retried — observed as a second request.**
    ///
    /// `Retry::Allowed` is chosen in `complete` and forwarded by the adapter;
    /// neither was pinned, and getting it wrong is not hypothetical — the
    /// comment on `Retry::Forbidden` records that this exact mistake once cost a
    /// real login against a live PDS, because servers rotate their nonce between
    /// PAR and the callback.
    ///
    /// The server challenges once, then answers. Two hits on `/token` means the
    /// retry happened; one means it did not.
    #[tokio::test]
    async fn a_nonce_challenge_on_the_token_endpoint_is_retried() {
        let cookie = flow::new_binding_token();
        let (addr, log) = spawn_tls(|addr| {
            let port = addr.port();
            let mut r = discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-e2e.test:{port}"),
            );
            r.insert(
                "/token".to_string(),
                vec![
                    TestResponse::json(400, "{\"error\":\"use_dpop_nonce\"}")
                        .with_header("DPoP-Nonce", "nonce-from-the-server"),
                    TestResponse::json(400, "{\"error\":\"invalid_grant\"}"),
                ],
            );
            r
        })
        .await;
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test"] {
            test_host_override(&fetcher, h, addr);
        }
        let port = addr.port();
        let issuer = format!("https://as-e2e.test:{port}");
        let stores =
            pending_against(&format!("https://pds-e2e.test:{port}"), &issuer, &cookie).await;
        let client = client_at("https://feather-reader.com");
        let mut params = callback_params();
        params.iss = Some(issuer);

        let _ = client
            .complete(
                &stores.deps(&fetcher, &StaticDns::new(), &MemoryNonces::new()),
                &params,
                Some(&cookie),
                1_700_000_000,
            )
            .await;

        let reqs = log.lock().unwrap().clone();
        let token_hits = reqs.iter().filter(|r| r.starts_with("POST /token")).count();
        assert_eq!(
            token_hits, 2,
            "a use_dpop_nonce challenge was not retried; the exchange is marked \
             non-retryable somewhere between complete and the wire",
        );
        let second = reqs
            .iter()
            .filter(|r| r.starts_with("POST /token"))
            .nth(1)
            .unwrap();
        // The nonce rides INSIDE the DPoP proof's claims, not as plaintext in
        // the request — asserting on the raw bytes would have passed for a retry
        // that ignored the challenge entirely.
        let claims = jwt_part(&dpop_proof(second), 1);
        assert_eq!(
            claims.get("nonce").and_then(|v| v.as_str()),
            Some("nonce-from-the-server"),
            "the retry did not carry the server's nonce; it would be challenged \
             again forever",
        );
    }

    /// **The token request uses the auth method the login was STARTED under.**
    ///
    /// A nine-line comment in `complete` explains why this must come from the
    /// pending row rather than the live runtime: a deploy that flipped
    /// dev/production between the push and the callback would otherwise present
    /// credentials that do not match the ones PAR was authenticated with, and the
    /// exchange fails for a reason nothing in the logs explains.
    ///
    /// Nothing tested it. Swapping `auth_method` for `client.auth_method()` in
    /// `token_exchange_params` passed the whole suite, because every fixture had
    /// the two agreeing. Here they disagree: the login was started under `none`
    /// while the runtime is configured for `private_key_jwt`, so a client
    /// assertion appearing in the token params can only have come from the
    /// runtime.
    #[tokio::test]
    async fn the_exchange_uses_the_auth_method_the_login_started_under() {
        let cookie = flow::new_binding_token();
        let stores = empty_stores().await;
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        pending.auth_method = AuthMethod::None;
        stores.pending.put(&pending).await.unwrap();

        // The runtime, by contrast, is a private_key_jwt client.
        let client = client_at("https://feather-reader.com");
        assert_eq!(
            client.auth_method().as_str(),
            "private_key_jwt",
            "fixture: the runtime must DISAGREE with the pending row",
        );

        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(out.is_ok(), "the exchange should complete: {out:?}");

        let calls = log.lock().unwrap();
        assert_eq!(
            calls.discovered[0].2, "none",
            "discovery was told the runtime's method, not the one PAR was pushed \
             under",
        );
        let params = &calls.posted[0].params;
        assert!(
            !params.iter().any(|(k, _)| *k == "client_assertion"),
            "a private_key_jwt assertion was sent for a login started under \
             `none`: {params:?}",
        );
    }

    /// **The client assertion's `aud`, and the session's, are the right hosts.**
    ///
    /// Two more values `complete` decides that nothing checked: swapping the
    /// assertion's audience from `pending.issuer` to `pending.pds_url`, and the
    /// stored session's `aud` the other way, each left the whole suite green
    /// despite being genuinely different hosts in the fixture.
    ///
    /// `aud` is the assertion's anti-replay binding — an assertion minted for one
    /// audience must not be accepted by another — and the session's `aud` is the
    /// audience every later DPoP-bound PDS call uses. The earlier tests inspected
    /// only whether `client_assertion` was PRESENT, never what was in it.
    #[tokio::test]
    async fn the_assertion_and_session_audiences_are_distinct_and_correct() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;
        assert!(out.is_ok());

        // The fixture's issuer and PDS are deliberately different hosts, so
        // these two assertions cannot both be satisfied by one value.
        let assertion = {
            let calls = log.lock().unwrap();
            calls.posted[0]
                .params
                .iter()
                .find(|(k, _)| *k == "client_assertion")
                .map(|(_, v)| v.clone())
                .expect("no client_assertion for a private_key_jwt login")
        };
        // Decoded inline rather than via a shared helper: this file is merged
        // into another branch that defines one, and two definitions would clash.
        let claims: serde_json::Value = {
            use base64::Engine as _;
            let seg = assertion.split('.').nth(1).expect("malformed assertion");
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(seg)
                .expect("assertion payload is not base64url");
            serde_json::from_slice(&raw).expect("assertion payload is not JSON")
        };
        assert_eq!(
            claims.get("aud").and_then(|v| v.as_str()),
            Some(PENDING_ISSUER),
            "the assertion was minted for the wrong audience; its anti-replay \
             binding names a server it was not sent to",
        );
        let stored = stores
            .sessions
            .get(PENDING_DID)
            .await
            .unwrap()
            .expect("session");
        assert_eq!(
            stored.aud, "https://pds.example.com",
            "the session's audience is not the PDS; every later DPoP-bound call \
             would carry the wrong `htu`/`aud`",
        );
    }

    /// **An expired pending row is refused — `now` really reaches the sweep.**
    ///
    /// `complete` passes `now` into `flow::complete_callback`, which is what lets
    /// `take_pending` prune expired rows. Passing `0` instead honoured a pending
    /// row long past its expiry — a sealed DPoP key and PKCE verifier that should
    /// have been swept — and the whole suite stayed green, because every fixture
    /// used an `expires_at` far in the future.
    ///
    /// `MAX_PENDING_SECS`'s COMPUTATION is pinned elsewhere; this pins that the
    /// bound is honoured.
    #[tokio::test]
    async fn an_expired_pending_row_is_refused() {
        let cookie = flow::new_binding_token();
        let stores = empty_stores().await;
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        // Expired an hour before the callback arrives.
        pending.expires_at = 1_700_000_000 - 3600;
        stores.pending.put(&pending).await.unwrap();

        let client = client_at("https://feather-reader.com");
        let (out, log) = drive(
            &stores,
            &client,
            &callback_params(),
            Some(&cookie),
            PENDING_ISSUER,
            200,
            token_body(PENDING_DID),
        )
        .await;

        assert!(out.is_err(), "an expired pending row completed a login");
        assert!(
            log.lock().unwrap().posted.is_empty(),
            "the authorization code was posted for an expired pending row",
        );
    }

    // ── calamus additions ────────────────────────────────────────────────────

    const NOW: i64 = 1_700_000_000;

    /// Decode a JWT's claims, unverified.
    fn claims_of(jwt: &str) -> serde_json::Value {
        jwt_part(jwt, 1)
    }

    // ── the identity-only flow (sign in with atproto, keep no tokens) ────────

    const E2E_HANDLE: &str = "alice-e2e.test";

    /// A PDS, its authorization server and a PLC directory on one TLS server:
    /// the account `alice-e2e.test` = [`PENDING_DID`], and a `/token` that grants
    /// `granted_sub`.
    async fn identity_world(
        granted_sub: &str,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        // Before the server is spawned: its leaf must cover the name.
        crate::testing::register_tls_host("plc-e2e.test");
        let granted_sub = granted_sub.to_string();
        spawn_tls(move |addr| {
            let port = addr.port();
            let pds = format!("https://pds-e2e.test:{port}");
            let issuer = format!("https://as-e2e.test:{port}");
            let mut r = discovery_routes(&pds, &issuer);
            r.insert(
                format!("/{PENDING_DID}"),
                vec![TestResponse::json(
                    200,
                    serde_json::json!({
                        "id": PENDING_DID,
                        "alsoKnownAs": [format!("at://{E2E_HANDLE}")],
                        "service": [{
                            "id": "#atproto_pds",
                            "type": "AtprotoPersonalDataServer",
                            "serviceEndpoint": pds,
                        }],
                    })
                    .to_string(),
                )],
            );
            r.insert(
                "/par".to_string(),
                vec![TestResponse::json(
                    201,
                    r#"{"request_uri":"urn:ietf:params:oauth:request_uri:e2e","expires_in":60}"#,
                )],
            );
            r.insert(
                "/token".to_string(),
                vec![TestResponse::json(
                    200,
                    token_body(&granted_sub).to_string(),
                )],
            );
            r
        })
        .await
    }

    /// The form body of a recorded request.
    fn form_of(raw: &str) -> Vec<(String, String)> {
        let body = raw.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    fn form_values<'a>(form: &'a [(String, String)], k: &str) -> Vec<&'a str> {
        form.iter()
            .filter(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// What one identity-only login left behind.
    struct IdentityRun {
        completed: Result<CompletedLogin>,
        /// Every request the server saw, in order.
        log: Vec<String>,
        pending: MemoryPendingLogins,
        /// The `state` PAR pushed.
        state: String,
        /// The client's published metadata document.
        document: serde_json::Value,
    }

    /// Log in as `alice-e2e.test` through the REAL `Client::start` and
    /// `Client::complete`, as a confidential client with an inline JWKS and the
    /// bare `atproto` scope, keeping no tokens (`store::Discard`). The browser's
    /// part is played by building the callback from what PAR pushed.
    async fn identity_only_login(granted_sub: &str) -> IdentityRun {
        let (addr, log) = identity_world(granted_sub).await;
        let port = addr.port();
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test", "plc-e2e.test"] {
            test_host_override(&fetcher, h, addr);
        }
        let txt = format!("did={PENDING_DID}");
        let dns = StaticDns::new().with_txt(&format!("_atproto.{E2E_HANDLE}."), &[&[&txt]]);

        let key = SigningKey::generate("identity-1");
        let metadata = ClientMetadata::confidential(
            url::Url::parse("https://identity.example.com/client-metadata.json").unwrap(),
            // A redirect on a different origin from the client_id.
            vec![url::Url::parse("https://wiki.example.net/_auth/callback").unwrap()],
            "atproto",
            "Identity only",
            None,
            Jwks::Inline(key.jwks_document().unwrap()),
        )
        .unwrap();
        let document = metadata.document();
        let client = Client::new(metadata, Some(key), format!("https://plc-e2e.test:{port}"))
            .expect("the identity-only client builds");

        let pending = MemoryPendingLogins::new();
        let nonces = MemoryNonces::new();
        let deps = Deps {
            fetcher: &fetcher,
            dns: &dns,
            pending: &pending,
            sessions: &Discard,
            nonces: &nonces,
        };
        let started = client
            .start(&deps, E2E_HANDLE, NOW)
            .await
            .expect("the identity-only login starts");

        let par = log
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.starts_with("POST /par"))
            .cloned()
            .expect("PAR was pushed");
        let state = form_values(&form_of(&par), "state")
            .first()
            .expect("PAR pushed a state")
            .to_string();
        let params = flow::CallbackParams {
            code: Some("the-code".into()),
            state: Some(state.clone()),
            iss: Some(format!("https://as-e2e.test:{port}")),
            ..Default::default()
        };
        let completed = client
            .complete(&deps, &params, Some(&started.binding_token), NOW)
            .await;

        let log = log.lock().unwrap().clone();
        IdentityRun {
            completed,
            log,
            pending,
            state,
            document,
        }
    }

    /// **The identity-only flow: the `sub` is verified, and no token is kept.**
    ///
    /// A client that only wants to know who the user is (sign in with atproto)
    /// runs the whole login against `store::Discard`. What it relies on: PAR
    /// asked for the bare `atproto` scope and nothing more, the DID it is handed
    /// is the one resolution produced (and the token response's `sub` agreed),
    /// and nothing holds the tokens afterwards.
    #[tokio::test]
    async fn an_identity_only_login_verifies_sub_and_stores_nothing() {
        let run = identity_only_login(PENDING_DID).await;
        let done = run.completed.expect("the identity-only login completes");

        assert_eq!(done.did, PENDING_DID, "not the DID resolution produced");
        assert_eq!(
            done.handle.as_deref(),
            Some(E2E_HANDLE),
            "the handle round-tripped through DNS and the DID document"
        );

        let par = run
            .log
            .iter()
            .find(|r| r.starts_with("POST /par"))
            .expect("PAR was pushed");
        let par = form_of(par);
        assert_eq!(
            form_values(&par, "scope"),
            vec!["atproto"],
            "PAR must ask for exactly the bare `atproto` scope"
        );
        assert_eq!(form_values(&par, "login_hint"), vec![E2E_HANDLE]);
        assert_eq!(
            form_values(&par, "client_id"),
            vec!["https://identity.example.com/client-metadata.json"]
        );

        let token_posts: Vec<&String> = run
            .log
            .iter()
            .filter(|r| r.starts_with("POST /token"))
            .collect();
        assert_eq!(token_posts.len(), 1, "the code was exchanged once");
        assert_eq!(
            form_values(&form_of(token_posts[0]), "client_assertion").len(),
            1,
            "a confidential client authenticates the exchange"
        );

        // Nothing kept: no session, and the pending login consumed.
        assert_eq!(Discard.get(PENDING_DID).await.unwrap(), None);
        assert!(
            run.pending.take(&run.state, NOW).await.unwrap().is_none(),
            "the pending login outlived its callback"
        );
        // The caller holds the only copy of the grant, to revoke it.
        assert_eq!(done.session.sub, PENDING_DID);
        assert_eq!(done.session.access_token, "at-abc");

        // The document a PDS fetches carries the keys inline.
        assert!(run.document.get("jwks").is_some());
        assert!(run.document.get("jwks_uri").is_none());
        assert_eq!(run.document["scope"], "atproto");
    }

    /// **Keeping no tokens does not relax the `sub` check.**
    ///
    /// The identity-only flow's whole output is the DID. A server granting
    /// tokens for another account must fail the login, not log the user in as
    /// that account with nothing stored to show for it.
    #[tokio::test]
    async fn an_identity_only_login_still_refuses_a_sub_mismatch() {
        let run = identity_only_login("did:plc:zzzzzzzzzzzzzzzzzzzzzzzz").await;
        let Err(err) = run.completed else {
            panic!("a token response for another DID completed an identity-only login")
        };
        assert!(
            format!("{err:#}").contains("different subject"),
            "refused, but not by the subject check: {err:#}",
        );
        assert_eq!(
            run.log
                .iter()
                .filter(|r| r.starts_with("POST /token"))
                .count(),
            1
        );
        // Nothing ran after the refusal: the only DID-document fetch is the
        // one `start` made. A handle lookup for the refused login would be a
        // second.
        assert_eq!(
            run.log
                .iter()
                .filter(|r| r.starts_with(&format!("GET /{PENDING_DID}")))
                .count(),
            1,
            "work continued after the subject check refused the login"
        );
    }

    // ── time at mint ──────────────────────────────────────────────────────────

    /// **The PAR assertion carries the time it was minted, not the time `start`
    /// was called.**
    ///
    /// Resolution and discovery are network round trips before the assertion
    /// is minted; an `iat` from the entry `now` is already old by then, by as
    /// much as those took. Paused time stands in for a slow resolution.
    #[tokio::test(start_paused = true)]
    async fn a_par_assertion_minted_after_a_slow_resolution_carries_the_advanced_iat() {
        let stores = empty_stores().await;
        let client = client_at("https://app.example.com");
        let pushed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&pushed);
        let started = start_with(
            &client,
            &stores.pending,
            "alice.example.com",
            NOW,
            |_subject| async move {
                tokio::time::advance(std::time::Duration::from_secs(120)).await;
                Ok(started_account())
            },
            |_p, _m, _e| async move { Ok(started_server()) },
            move |req: ParPost| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(req);
                    Ok(par_ok())
                }
            },
        )
        .await;
        assert!(started.is_ok());

        let (assertion, state) = {
            let pushed = pushed.lock().unwrap();
            (
                param(&pushed[0].params, "client_assertion")
                    .expect("a client assertion")
                    .to_string(),
                pushed_state_of(&pushed[0]),
            )
        };
        assert_eq!(
            claims_of(&assertion)["iat"].as_i64(),
            Some(NOW + 120),
            "the assertion's iat is the entry time, not the time it was minted"
        );
        let pending = stores.pending.take(&state, NOW).await.unwrap().unwrap();
        assert_eq!(
            pending.expires_at,
            NOW + 120 + 60,
            "the pending row's lifetime counts from when PAR answered"
        );
    }

    fn pushed_state_of(req: &ParPost) -> String {
        param(&req.params, "state").expect("state").to_string()
    }

    /// **The token-request assertion, and the session's expiry, carry the time
    /// after re-discovery.**
    #[tokio::test(start_paused = true)]
    async fn a_token_assertion_minted_after_a_slow_discovery_carries_the_advanced_iat() {
        let cookie = flow::new_binding_token();
        let stores = pending_login(&flow::binding_hash(&cookie)).await;
        let client = client_at("https://feather-reader.com");
        let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&posted);
        let body = serde_json::to_vec(&token_body(PENDING_DID)).unwrap();
        let out = complete_with(
            &client,
            &stores.pending,
            &stores.sessions,
            &callback_params(),
            Some(&cookie),
            NOW,
            |_req| async move {
                tokio::time::advance(std::time::Duration::from_secs(120)).await;
                Ok(server_at(PENDING_ISSUER))
            },
            move |req: TokenPost| {
                let sink = std::sync::Arc::clone(&sink);
                let body = body.clone();
                async move {
                    sink.lock().unwrap().push(req.params);
                    Ok((PostOutcome { status: 200, body }, req.clock.now()))
                }
            },
            |_did| async move { Err(anyhow::anyhow!("offline")) },
        )
        .await;
        assert!(out.is_ok(), "the exchange should complete: {out:?}");

        let assertion = {
            let posted = posted.lock().unwrap();
            param(&posted[0], "client_assertion")
                .expect("a client assertion")
                .to_string()
        };
        assert_eq!(
            claims_of(&assertion)["iat"].as_i64(),
            Some(NOW + 120),
            "the assertion's iat is the entry time, not the time it was minted"
        );
        let stored = stores.sessions.get(PENDING_DID).await.unwrap().unwrap();
        assert_eq!(
            stored.expires_at,
            Some(NOW + 120 + 3600),
            "the session's expiry counts from when the token response arrived"
        );
    }

    /// **One clock from the callback to the token proof.** 0.6 s taking the
    /// pending row and 0.6 s reading the nonce is 1.2 s; re-anchoring in the
    /// transport at the truncated second made the proof say 0 s. Driven
    /// through [`Client::complete`] over real TLS, so the production adapter
    /// is what carries the clock.
    #[tokio::test]
    async fn a_token_proof_after_nested_waits_counts_every_fraction_once() {
        let cookie = flow::new_binding_token();
        let (addr, log) = spawn_tls(|addr| {
            let port = addr.port();
            let mut r = discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-e2e.test:{port}"),
            );
            r.insert(
                "/token".to_string(),
                vec![TestResponse::json(200, token_body(PENDING_DID).to_string())],
            );
            r
        })
        .await;
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test"] {
            test_host_override(&fetcher, h, addr);
        }
        let port = addr.port();
        let issuer = format!("https://as-e2e.test:{port}");
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        pending.pds_url = format!("https://pds-e2e.test:{port}");
        pending.issuer = issuer.clone();
        let slow_pending = crate::testing::slow::SlowPending {
            on_take: std::time::Duration::from_millis(600),
            ..Default::default()
        };
        slow_pending.inner.put(&pending).await.unwrap();
        let nonces = crate::testing::slow::SlowNonces {
            on_get: std::time::Duration::from_millis(600),
            ..Default::default()
        };
        let sessions = MemorySessions::new();
        let dns = StaticDns::new();
        let deps = Deps {
            fetcher: &fetcher,
            dns: &dns,
            pending: &slow_pending,
            sessions: &sessions,
            nonces: &nonces,
        };
        let mut params = callback_params();
        params.iss = Some(issuer);

        client_at("https://feather-reader.com")
            .complete(&deps, &params, Some(&cookie), NOW)
            .await
            .expect("the login completes");

        let token_req = log
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.starts_with("POST /token"))
            .cloned()
            .expect("the token endpoint was never reached");
        let iat = claims_of(&dpop_proof(&token_req))["iat"].as_i64().unwrap();
        assert!(
            (NOW + 1..NOW + 3).contains(&iat),
            "1.2 s after the entry, the token proof carried iat NOW{:+}",
            iat - NOW
        );
    }

    /// **The session's expiry counts from when the token proof was minted.**
    ///
    /// The token response offers a nonce whose store takes 60 s: anchored after
    /// the response, the expiry said NOW+3600+60, a minute later than the
    /// server can have meant. The refresh has counted from the proof's mint
    /// time since 8890b76; the login is the same rule.
    #[tokio::test]
    async fn a_session_expiry_counts_from_the_token_proofs_mint_time() {
        let cookie = flow::new_binding_token();
        let (addr, _log) = spawn_tls(|addr| {
            let port = addr.port();
            let mut r = discovery_routes(
                &format!("https://pds-e2e.test:{port}"),
                &format!("https://as-e2e.test:{port}"),
            );
            r.insert(
                "/token".to_string(),
                vec![TestResponse::json(200, token_body(PENDING_DID).to_string())
                    .with_header("DPoP-Nonce", "after")],
            );
            r
        })
        .await;
        let fetcher = Fetcher::default();
        for h in ["pds-e2e.test", "as-e2e.test"] {
            test_host_override(&fetcher, h, addr);
        }
        let port = addr.port();
        let issuer = format!("https://as-e2e.test:{port}");
        let mut pending = pending_auth(&flow::binding_hash(&cookie));
        pending.pds_url = format!("https://pds-e2e.test:{port}");
        pending.issuer = issuer.clone();
        let stores = Stores::default();
        stores.pending.put(&pending).await.unwrap();
        let nonces = crate::testing::slow::SlowNonces {
            on_put: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let dns = StaticDns::new();
        let deps = Deps {
            fetcher: &fetcher,
            dns: &dns,
            pending: &stores.pending,
            sessions: &stores.sessions,
            nonces: &nonces,
        };
        let mut params = callback_params();
        params.iss = Some(issuer);

        let done = client_at("https://feather-reader.com")
            .complete(&deps, &params, Some(&cookie), NOW)
            .await
            .expect("the login completes");
        let expires_at = done.session.expires_at.unwrap();
        assert!(
            (NOW + 3600..NOW + 3603).contains(&expires_at),
            "the expiry was anchored after the response: NOW+3600{:+}",
            expires_at - NOW - 3600
        );
    }

    /// Two confidential clients with ONE redirect and different `client_id`s:
    /// the redirect comparison cannot tell them apart.
    fn client_with_id(client_id: &str) -> Client {
        let at = |u: &str| url::Url::parse(u).unwrap();
        let metadata = ClientMetadata::confidential(
            at(client_id),
            vec![at("https://app.example.com/oauth/callback")],
            "atproto transition:generic",
            "App",
            None,
            Jwks::Uri(at("https://app.example.com/oauth/jwks.json")),
        )
        .unwrap();
        Client::new(
            metadata,
            Some(SigningKey::generate("k")),
            "https://plc.invalid",
        )
        .unwrap()
    }

    /// **A login is completed only under the `client_id` it was started
    /// under.** In calamus the `client_id` and the redirect are independent
    /// (FeatherReader derives both from one public URL), so comparing the
    /// redirect alone let a pending login pushed as one client be redeemed as
    /// another: the code, the PKCE verifier and an assertion for the second
    /// client all posted to the token endpoint, which rejects them for a
    /// reason nothing here explains. Refused before discovery or any POST.
    #[tokio::test]
    async fn a_login_completed_under_another_client_id_posts_nothing() {
        let started_as = client_with_id("https://app.example.com/oauth/client-metadata.json");
        let completed_as = client_with_id("https://app.example.com/oauth/other-metadata.json");

        for (completer, refused) in [(&completed_as, true), (&started_as, false)] {
            let stores = empty_stores().await;
            let (started, pushed) = run_start(&started_as, &stores, NOW).await;
            let started = started.expect("the start succeeds");
            let params = flow::CallbackParams {
                code: Some("the-code".into()),
                state: Some(pushed_state(&pushed)),
                iss: Some(START_ISSUER.into()),
                ..Default::default()
            };
            let posts = std::sync::Arc::new(std::sync::Mutex::new(0usize));
            let discoveries = std::sync::Arc::new(std::sync::Mutex::new(0usize));
            let (p, d) = (posts.clone(), discoveries.clone());
            let out = complete_with(
                completer,
                &stores.pending,
                &stores.sessions,
                &params,
                Some(&started.binding_token),
                NOW,
                move |_req| {
                    *d.lock().unwrap() += 1;
                    async move { Ok(started_server()) }
                },
                move |req: TokenPost| {
                    *p.lock().unwrap() += 1;
                    let invalid = outcome(400, &serde_json::json!({"error": "invalid_grant"}));
                    async move { Ok((invalid, req.clock.now())) }
                },
                |_did| async move { Err(anyhow::anyhow!("offline")) },
            )
            .await;
            let err = format!("{:#}", out.expect_err("the stub exchange fails either way"));
            if refused {
                assert!(
                    err.contains("client_id"),
                    "refused, but not BY the client_id check: {err}"
                );
                assert_eq!(
                    *posts.lock().unwrap(),
                    0,
                    "posted to the token endpoint as another client"
                );
                assert_eq!(
                    *discoveries.lock().unwrap(),
                    0,
                    "discovered before refusing"
                );
            } else {
                assert!(
                    !err.contains("client_id"),
                    "the same client was refused: {err}"
                );
                assert_eq!(
                    *posts.lock().unwrap(),
                    1,
                    "the same client never reached the token endpoint"
                );
            }
        }
    }

    // ── the Client itself ─────────────────────────────────────────────────────

    /// **A client whose key does not fit its metadata is refused at
    /// construction**, not at the first login: a confidential client without
    /// its key cannot sign an assertion, and the dev client is public and must
    /// not hold one it would never use.
    #[test]
    fn a_client_refuses_a_key_that_does_not_fit_its_metadata() {
        let confidential = ClientMetadata::confidential(
            url::Url::parse("https://app.example.com/oauth/client-metadata.json").unwrap(),
            vec![url::Url::parse("https://app.example.com/oauth/callback").unwrap()],
            "atproto",
            "App",
            None,
            Jwks::Uri(url::Url::parse("https://app.example.com/oauth/jwks.json").unwrap()),
        )
        .unwrap();
        let err = Client::new(confidential, None, "https://plc.directory")
            .expect_err("a confidential client without its key");
        assert!(format!("{err:#}").contains("signing key"), "{err:#}");

        let dev = ClientMetadata::localhost_dev(
            url::Url::parse("http://127.0.0.1:8080/oauth/callback").unwrap(),
            "atproto",
            "App",
        )
        .unwrap();
        let err = Client::new(
            dev,
            Some(SigningKey::generate("k")),
            "https://plc.directory",
        )
        .expect_err("a public client holding a key");
        assert!(format!("{err:#}").contains("public"), "{err:#}");
    }

    /// **An inline JWKS must publish the client's own key.** The
    /// authorization server verifies every client assertion against the
    /// published JWKS, by `kid`: a key that is not in it (another key, or the
    /// right key under another `kid`) signs assertions no server can verify,
    /// and every login and refresh fails at the server instead of here.
    #[test]
    fn a_client_refuses_a_key_its_inline_jwks_does_not_publish() {
        let inline = |jwks: serde_json::Value| {
            ClientMetadata::confidential(
                url::Url::parse("https://app.example.com/oauth/client-metadata.json").unwrap(),
                vec![url::Url::parse("https://app.example.com/oauth/callback").unwrap()],
                "atproto",
                "App",
                None,
                Jwks::Inline(jwks),
            )
            .unwrap()
        };
        let key = SigningKey::generate("k1");
        let copy = || SigningKey::from_jwk_json(&key.to_jwk_json().unwrap(), "k1").unwrap();

        let other = SigningKey::generate("k1").jwks_document().unwrap();
        let err = Client::new(inline(other), Some(copy()), "https://plc.directory")
            .expect_err("a key the inline JWKS does not publish");
        assert!(format!("{err:#}").contains("inline JWKS"), "{err:#}");

        let mut renamed = key.jwks_document().unwrap();
        renamed["keys"][0]["kid"] = "k2".into();
        let err = Client::new(inline(renamed), Some(copy()), "https://plc.directory")
            .expect_err("the right key under another kid");
        assert!(format!("{err:#}").contains("inline JWKS"), "{err:#}");

        // Published (beside another key): accepted.
        let mut both = SigningKey::generate("k0").jwks_document().unwrap();
        both["keys"]
            .as_array_mut()
            .unwrap()
            .push(key.public_jwk().unwrap());
        Client::new(inline(both), Some(copy()), "https://plc.directory")
            .expect("a key the inline JWKS publishes");
    }

    /// The client's identity comes from its metadata, so what it sends and
    /// what it publishes cannot disagree.
    #[test]
    fn the_client_identity_is_the_metadatas() {
        let client = client_at("https://feather-reader.com");
        assert_eq!(
            client.client_id(),
            "https://feather-reader.com/oauth/client-metadata.json"
        );
        assert_eq!(client.client_id(), client.metadata().client_id());
        assert_eq!(client.auth_method(), AuthMethod::PrivateKeyJwt);
        assert_eq!(client.plc_directory(), "https://plc.invalid");

        let dev = client_at("http://127.0.0.1:8080");
        assert_eq!(dev.auth_method(), AuthMethod::None);
        assert!(dev.key().is_none());
    }

    /// **`Debug` never prints a secret**: the binding token and the
    /// `request_uri` of a started login, a completed login's tokens and DPoP
    /// key, and the client's signing key.
    #[test]
    fn debug_output_redacts_every_secret() {
        let started = StartedLogin {
            authorize_url:
                "https://as.example.com/authorize?client_id=x&request_uri=urn%3Asecret-request-uri"
                    .into(),
            binding_token: "secret-binding-token".into(),
        };
        let shown = format!("{started:?}");
        assert!(
            shown.contains("https://as.example.com/authorize"),
            "{shown}"
        );
        for secret in ["secret-binding-token", "secret-request-uri"] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }

        let completed = CompletedLogin {
            did: PENDING_DID.into(),
            handle: Some("alice.example.com".into()),
            session: Session {
                sub: PENDING_DID.into(),
                issuer: PENDING_ISSUER.into(),
                aud: "https://pds.example.com".into(),
                dpop_key_jwk: "secret-dpop-jwk".into(),
                access_token: "secret-access".into(),
                refresh_token: "secret-refresh".into(),
                token_type: "DPoP".into(),
                granted_scope: "atproto".into(),
                expires_at: None,
            },
        };
        let shown = format!("{completed:?}");
        assert!(shown.contains(PENDING_DID), "{shown}");
        for secret in ["secret-dpop-jwk", "secret-access", "secret-refresh"] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }

        let client = client_at("https://feather-reader.com");
        let private = client.key().unwrap().to_jwk_json().unwrap();
        let d: serde_json::Value = serde_json::from_str(&private).unwrap();
        let d = d["d"].as_str().unwrap().to_string();
        let shown = format!("{client:?}");
        assert!(!shown.contains(&d), "the client's private key in {shown}");
        assert!(shown.contains("featherreader-oauth-1"), "{shown}");
    }

    /// `start` and `complete` can be spawned on a multi-threaded runtime, for
    /// every store and resolver.
    #[test]
    fn the_login_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn send_sync<T: Send + Sync>() {}
        fn generic<D: DnsResolver, P: PendingLoginStore, S: SessionStore, N: NonceStore>(
            client: &Client,
            deps: &Deps<'_, D, P, S, N>,
            params: &flow::CallbackParams,
        ) {
            assert_send(&client.start(deps, "alice.example.com", 0));
            assert_send(&client.complete(deps, params, None, 0));
        }
        send_sync::<Client>();
        let stores = Stores::default();
        let (fetcher, dns, nonces) = (Fetcher::default(), StaticDns::new(), MemoryNonces::new());
        generic(
            &client_at("https://feather-reader.com"),
            &stores.deps(&fetcher, &dns, &nonces),
            &flow::CallbackParams::default(),
        );
    }
}
