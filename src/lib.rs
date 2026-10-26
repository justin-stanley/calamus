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
pub mod client_auth;
pub mod flow;
pub mod metadata;
