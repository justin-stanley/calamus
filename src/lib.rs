//! An [atproto](https://atproto.com) OAuth client, for apps that sign people in
//! with their atproto identity (Bluesky or any PDS).
//!
//! calamus does the whole client side of the
//! [atproto OAuth profile](https://atproto.com/specs/oauth):
//!
//! - **identity**: handle → DID (DNS TXT or `/.well-known/atproto-did`, then
//!   verified back), DID → PDS, for `did:plc` and `did:web`;
//! - **discovery** of the PDS's authorization server, with the issuer checks
//!   that stop a server from claiming another's accounts;
//! - **PAR + PKCE (S256) + DPoP**, with server nonces handled;
//! - **`private_key_jwt`** client authentication for confidential clients, or
//!   none for the localhost development client;
//! - the **callback**: `state`, RFC 9207 `iss`, the browser-binding check, the
//!   code exchange, and the token response's `sub` checked against the DID the
//!   login started from;
//! - **sessions**: refresh with single-use rotating refresh tokens, serialized
//!   per account, and **revocation** (RFC 7009) on sign-out;
//! - **XRPC calls** to the user's PDS with DPoP-bound tokens (feature `xrpc`).
//!
//! Every one of those steps fetches a URL someone else chose, so every request
//! goes through [`net::Fetcher`], an **SSRF-guarded HTTP client**: it refuses
//! private, loopback, link-local and other non-public addresses after DNS
//! resolution and on every redirect hop, caps bodies and timeouts, and never
//! forwards credentials across origins.
//!
//! It runs in production in [FeatherReader](https://github.com/justin-stanley/feather-reader),
//! an atproto-native feed reader, where it was written before being extracted
//! here.
//!
//! # Signing someone in
//!
//! ```no_run
//! # #[cfg(feature = "dns")]
//! # async fn example(now: i64, callback: calamus::flow::CallbackParams, cookie: &str) -> anyhow::Result<()> {
//! use calamus::keys::SigningKey;
//! use calamus::login::{Client, Deps};
//! use calamus::metadata::{ClientMetadata, Jwks};
//! use calamus::net::{FetchPolicy, Fetcher};
//! use calamus::resolve::SystemResolver; // feature `dns` (default)
//! use calamus::store::memory::{MemoryNonces, MemoryPendingLogins, MemorySessions};
//! use url::Url;
//!
//! // Once, at startup. Persist the key: it is the client's identity.
//! let key = SigningKey::generate("my-app-1");
//! let metadata = ClientMetadata::confidential(
//!     Url::parse("https://app.example/oauth/client-metadata.json")?,
//!     vec![Url::parse("https://app.example/oauth/callback")?],
//!     "atproto transition:generic",
//!     "My App",
//!     None,
//!     Jwks::Inline(key.jwks_document()?),
//! )?;
//! let client = Client::new(metadata, Some(key), "https://plc.directory")?;
//! let fetcher = Fetcher::new(FetchPolicy::default())?;
//! let dns = SystemResolver::from_system_config()?;
//! // In-memory stores, for one process; implement the `store` traits on your
//! // database to survive restarts and run more than one instance.
//! let (pending, sessions, nonces) =
//!     (MemoryPendingLogins::new(), MemorySessions::new(), MemoryNonces::new());
//! let deps = Deps { fetcher: &fetcher, dns: &dns, pending: &pending, sessions: &sessions, nonces: &nonces };
//!
//! // The user submits their handle: send the browser to `authorize_url` and set
//! // `binding_token` as a cookie.
//! let started = client.start(&deps, "alice.bsky.social", now).await?;
//!
//! // The authorization server redirects back to your callback with these
//! // query parameters; the browser presents the cookie.
//! let login = client.complete(&deps, &callback, Some(cookie), now).await?;
//! println!("signed in as {}", login.did);
//! # let _ = started; Ok(()) }
//! ```
//!
//! A complete flow, including refresh and sign-out, runs offline in
//! `examples/sign_in.rs` against `testing::fake` (feature `test-util`).
//!
//! # Wiring it into a web app
//!
//! If your pages send a `Content-Security-Policy` with `form-action 'self'`,
//! don't answer the sign-in form's POST with a redirect to `authorize_url`:
//! browsers apply `form-action` to the redirect too, and Chrome and Safari
//! refuse it silently, so the sign-in button appears to do nothing. Answer with
//! a page that continues with `<meta http-equiv="refresh">` and a link instead.
//! FeatherReader hit this and fixed it that way.
//!
//! # Modules
//!
//! | module | what it does |
//! |---|---|
//! | [`login`] | [`login::Client`]: start and complete a login |
//! | [`session`] | keep a session valid, refreshing it when stale |
//! | [`revoke`] | revoke tokens; `revoke::sign_out` with feature `revoke` |
//! | `xrpc` | DPoP-bound calls to the user's PDS (feature `xrpc`) |
//! | [`store`] | the storage traits you implement, and in-memory versions |
//! | [`metadata`] | the client-metadata document you publish |
//! | [`keys`] | the client's ES256 signing key and its JWKS |
//! | [`resolve`], [`identity`] | handle and DID resolution |
//! | [`discovery`] | finding and checking the authorization server |
//! | [`net`] | the SSRF-guarded fetcher |
//! | [`dpop`], [`client_auth`], [`flow`], [`token`], [`jwt`], [`request`], [`fetch`] | the protocol pieces the above are built from |
//! | [`error`] | [`Error`], the typed decisions a caller can match on |
//!
//! # Features
//!
//! | feature | default | adds |
//! |---|---|---|
//! | `dns` | yes | `resolve::SystemResolver`: handle lookup by DNS TXT through the system resolver |
//! | `revoke` | no | `revoke::sign_out` and `sign_out_with` (the RFC 7009 request itself is always built) |
//! | `xrpc` | no | `xrpc::Repo`: DPoP-bound XRPC calls |
//! | `test-util` | no | `testing`: the fake authorization server, PDS, PLC and DNS, `testing::store_contract` (the rules a store must keep), and `client_auth::record_evidence`. **Only ever in `[dev-dependencies]`**: it can bypass the SSRF guard for named hosts |
//!
//! # Time
//!
//! Functions take the time as `now` (Unix seconds) rather than reading a clock,
//! so tests can pin it.

// docs.rs builds with every feature and `--cfg docsrs`: label each item with the
// feature it needs.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/justin-stanley/calamus/main/assets/calamus-mark-light.svg"
)]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/justin-stanley/calamus/main/assets/favicon.svg"
)]

pub mod error;
pub mod identity;
pub mod jwt;
pub mod keys;
pub mod token;

pub use error::Error;

/// Largest error body any path here will parse looking for one field.
///
/// **An error document is a few dozen bytes; the question is what a server can
/// make us deserialise on a path that runs for every failure.** A capped read
/// still admits megabytes, and 8 MB of cheap JSON structure builds hundreds of
/// megabytes of `serde_json::Value` (measured in FeatherReader: 789 MB for one
/// 8 MB body of `{"":0}` objects). Every path that peeks at a failed response for
/// a single string field (the DPoP nonce challenge, an XRPC error's
/// `error`/`message`, and the refresh classifier's `invalid_grant`) is bounded by
/// this one constant.
///
/// 10 KiB matches the reference client's own peek.
///
/// Ported from FeatherReader `src/oauth/mod.rs`.
pub const MAX_ERROR_BODY: usize = 10 * 1024;

/// Whether a failed response's body is small enough to be worth parsing for one
/// field. See [`MAX_ERROR_BODY`].
///
/// Refusing to look is always safe here: every caller is extracting a hint for a
/// decision it already has a default for — retry, transient, "no message".
pub fn error_body_worth_parsing(body: &[u8]) -> bool {
    !body.is_empty() && body.len() <= MAX_ERROR_BODY
}
/// The caller's `now`, advanced by the time elapsed since it was handed in.
///
/// Every function here takes the time as `now` (Unix seconds) instead of reading
/// a clock, so tests can pin it. But one call can await for a long time (a
/// refresh lock, a token request plus its nonce retry, a revocation, several
/// sign-out attempts), and a proof or client assertion minted at the end must
/// carry the time it is MINTED, not the time the call began. So each such
/// function captures this at entry and reads [`Elapsing::now`] at every mint.
/// It counts on tokio's clock, which a test can pause and advance.
///
/// **Captured once per public call and handed down**, never re-anchored at
/// [`Elapsing::now`]: that is whole seconds, so each nested call that started
/// its own count from it dropped up to a second (valid_session, the refresh,
/// the request: up to ~3 s behind).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Elapsing {
    base: i64,
    start: tokio::time::Instant,
}

impl From<i64> for Elapsing {
    /// Start counting from `now`.
    fn from(now: i64) -> Self {
        Self {
            base: now,
            start: tokio::time::Instant::now(),
        }
    }
}

impl Elapsing {
    /// `now` plus the whole seconds elapsed since the count began.
    pub(crate) fn now(&self) -> i64 {
        let elapsed = i64::try_from(self.start.elapsed().as_secs()).unwrap_or(i64::MAX);
        self.base.saturating_add(elapsed)
    }
}

pub mod client_auth;
pub mod discovery;
pub mod dpop;
pub mod fetch;
pub mod flow;
pub mod login;
pub mod metadata;
pub mod net;
pub mod request;
pub mod resolve;
pub mod revoke;
pub mod session;
pub mod store;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
#[cfg(feature = "xrpc")]
pub mod xrpc;
