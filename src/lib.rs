//! calamus: an atproto OAuth client library, extracted from FeatherReader.
//!
//! See `design/EXTRACTION-PLAN.md` for what each module is and the order they arrive in.

pub mod identity;
pub mod jwt;
pub mod keys;
pub mod token;

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
#[derive(Debug, Clone, Copy)]
pub(crate) struct Elapsing {
    base: i64,
    start: tokio::time::Instant,
}

impl Elapsing {
    /// Start counting from `now`.
    pub(crate) fn from(now: i64) -> Self {
        Self {
            base: now,
            start: tokio::time::Instant::now(),
        }
    }

    /// `now` plus the whole seconds elapsed since [`Elapsing::from`].
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
