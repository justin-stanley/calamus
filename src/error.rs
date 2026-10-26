//! The decisions a caller branches on, as types.
//!
//! **Every public function still returns `anyhow::Result`.** At each point
//! where calamus makes a decision a caller acts on (an SSRF refusal, a refused
//! redirect, a mix-up, an unknown `state`, a foreign browser, a dead grant...),
//! the error it returns is an [`Error`], so a caller asks
//!
//! ```ignore
//! match calamus::Error::find(&err) {
//!     Some(calamus::Error::Callback(CallbackError::BindingMismatch)) => ...,
//!     Some(e) if e.invalidates_session() => ...,
//!     _ => ...,
//! }
//! ```
//!
//! instead of matching on the message. [`Error::find`] walks the chain, so
//! context the caller (or calamus) added above it does not hide it.
//!
//! **No message changed.** Each variant's `Display` is byte-for-byte the text
//! the `bail!` it replaced produced, and no variant has a `source()` of its own,
//! so `{err:#}` (context, then the chain) renders exactly as before. The
//! `e2e_errors` suite pins the messages callers match on.
//!
//! **Why not `Result<T, calamus::Error>`.** Most failures here are not decisions
//! (a malformed document, an I/O error, a store error with the caller's own
//! context), and FeatherReader adds `.context(...)` to calamus's errors and
//! already finds typed causes with `err.chain().find_map(downcast_ref)`. Keeping
//! `anyhow` means no signature changes, no adapter at any call site, and
//! `{err:#}` unchanged by construction; a caller that wants a concrete error type
//! converts with `Error::from(anyhow::Error)`, which recovers the variant (or
//! keeps the whole error, context and all, as [`Error::Other`]).
//!
//! **Typed leaves that predate this** stay as they are, and are found the same
//! way (`err.chain().find_map(|c| c.downcast_ref::<T>())`):
//! [`crate::net::BodyTooLarge`], [`crate::net::BodyReadFailed`],
//! [`crate::fetch::StructureExplosion`], and with the `xrpc` feature
//! `xrpc::XrpcError`. Folding them in would change what `downcast_ref` finds
//! for code that already relies on them.

use std::net::IpAddr;

use crate::token::RefreshFailure;

/// A decision calamus made that a caller may branch on.
///
/// Reached from an `anyhow::Error` with [`Error::find`]. `Display` is exactly
/// the message the error always had.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The SSRF guard refused a target: `ip` is internal (loopback, private,
    /// link-local, metadata, ...). `host` is the URL's host as written; for an
    /// IP literal it is that IP (unbracketed), otherwise the name that
    /// resolved to `ip`.
    #[error("{}", ssrf_message(host, ip))]
    Ssrf {
        /// The host as written in the URL (an IP literal, or a name).
        host: String,
        /// The forbidden address.
        ip: IpAddr,
    },

    /// A redirect (or other `3xx`) was refused rather than followed.
    #[error("{}", redirect_message(*status, url, refusal))]
    RedirectRefused {
        /// The response status.
        status: u16,
        /// The URL that was being fetched (as the caller gave it).
        url: String,
        /// Which refusal.
        refusal: RedirectRefusal,
    },

    /// A handle or DID could not be resolved to an account.
    #[error(transparent)]
    Resolution(#[from] ResolutionError),

    /// Authorization-server discovery refused what it found.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),

    /// The authorization callback was refused.
    #[error(transparent)]
    Callback(#[from] CallbackError),

    /// A token-endpoint (or PAR) request failed or was refused.
    #[error(transparent)]
    Token(#[from] TokenError),

    /// A refresh failed at the authorization server. `failure` says what that
    /// means for the stored session: [`RefreshFailure::SessionInvalid`] (it was
    /// removed; the user must log in again) or [`RefreshFailure::Transient`] (it
    /// was left intact).
    #[error("{}", refresh_message(*failure, sub, *status))]
    Refresh {
        /// What the failure means for the session.
        failure: RefreshFailure,
        /// The subject whose refresh failed.
        sub: String,
        /// The token endpoint's status.
        status: u16,
    },

    /// There is no session for `sub` (or it went away while being used).
    #[error("{}", no_session_message(sub, gone))]
    NoSession {
        /// The subject asked for.
        sub: String,
        /// When it was found missing.
        gone: SessionGone,
    },

    /// A revocation request failed before or at the server.
    #[error(transparent)]
    Revoke(#[from] RevokeError),

    /// Anything else: an error with no decision behind it, kept whole (its
    /// context and chain), from `Error::from(anyhow::Error)`. Calamus itself
    /// never puts one in an `anyhow::Error`.
    #[error(transparent)]
    Other(anyhow::Error),
}

impl Error {
    /// The calamus decision behind `err`, wherever it sits in the chain.
    pub fn find(err: &anyhow::Error) -> Option<&Error> {
        err.chain().find_map(|cause| cause.downcast_ref::<Error>())
    }

    /// Whether this means the session is gone and the user must log in again:
    /// a refresh rejected as `invalid_grant`, or no session at all.
    pub fn invalidates_session(&self) -> bool {
        matches!(
            self,
            Error::Refresh {
                failure: RefreshFailure::SessionInvalid,
                ..
            } | Error::NoSession { .. }
        )
    }
}

impl From<anyhow::Error> for Error {
    /// The variant, when `err` IS a calamus error with nothing above it;
    /// otherwise [`Error::Other`], keeping its context and chain (whose `Display`
    /// is then exactly `err`'s).
    fn from(err: anyhow::Error) -> Self {
        match err.downcast::<Error>() {
            Ok(typed) => typed,
            Err(err) => Error::Other(err),
        }
    }
}

/// Why a redirect was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedirectRefusal {
    /// A fetch that must not be moved (a discovery or DID document) was
    /// redirected.
    NotFollowed,
    /// A `3xx` that names no single followable target (`300`, `305`, ...).
    NoSingleTarget,
    /// A POST was redirected; following would re-send its body.
    OnPost {
        /// The `Location` header, or `<none>`.
        location: String,
    },
}

/// Why a handle or DID did not resolve.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResolutionError {
    /// Not a valid handle. `handle` is the input as given.
    #[error("handle {handle:?} {problem}")]
    InvalidHandle {
        /// The input, as given.
        handle: String,
        /// What is wrong with it.
        problem: HandleProblem,
    },
    /// A DID method other than `did:plc` and `did:web`.
    #[error("unsupported DID method in {did:?}; only did:plc and did:web are resolvable")]
    UnsupportedDidMethod {
        /// The DID.
        did: String,
    },
    /// The DID document served is another DID's.
    #[error("DID document id {id:?} does not match the requested DID {expected:?}")]
    DidDocumentMismatch {
        /// The document's `id`.
        id: String,
        /// The DID that was requested.
        expected: String,
    },
    /// The DID document names no PDS.
    #[error("DID document declares no #atproto_pds service for {did}")]
    NoPds {
        /// The DID.
        did: String,
    },
    /// The DID document claims no handle, so a handle cannot be verified
    /// against it.
    #[error("DID document claims no handle; cannot verify bidirectionally")]
    NoClaimedHandle,
    /// The DID document claims another handle than the one resolved.
    #[error("DID document claims handle {claimed:?}, not {wanted:?}")]
    HandleMismatch {
        /// The handle the document claims (normalized).
        claimed: String,
        /// The handle that was resolved (normalized).
        wanted: String,
    },
}

/// What is wrong with a handle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandleProblem {
    /// Empty, or longer than 253.
    #[error("has an invalid length")]
    InvalidLength,
    /// Fewer than two segments.
    #[error("must have at least two segments")]
    TooFewSegments,
    /// A segment empty or longer than 63.
    #[error("has an empty or over-long segment")]
    SegmentLength,
    /// A character other than ASCII alphanumerics and `-`.
    #[error("has a segment with illegal characters")]
    IllegalCharacters,
    /// A segment starting or ending with `-`.
    #[error("has a segment starting or ending with a hyphen")]
    EdgeHyphen,
    /// The TLD starts with a digit.
    #[error("has a TLD starting with a digit")]
    NumericTld,
    /// A reserved TLD (`.local`, `.test`, ...), without its dot.
    #[error("uses the reserved TLD .{0}")]
    ReservedTld(String),
}

/// Why discovery refused what it found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// **The mix-up defence.** Re-discovery found another authorization
    /// server than the one the grant belongs to; nothing was sent to it.
    #[error(
        "the PDS now names a different authorization server ({discovered:?}) than this \
         grant was issued by ({expected:?}); refusing to send credentials to it"
    )]
    IssuerMismatch {
        /// The issuer the PDS names now.
        discovered: String,
        /// The issuer the grant was issued by.
        expected: String,
    },
    /// The authorization-server metadata claims another issuer than the one it
    /// was fetched from (RFC 8414 §3.3).
    #[error("authorization-server declares issuer {declared:?} but was fetched from {fetched:?}")]
    MetadataIssuerMismatch {
        /// The document's `issuer`.
        declared: String,
        /// The issuer it was fetched from.
        fetched: String,
    },
    /// An endpoint is not on the issuer's own origin.
    #[error(
        "`{field}` {url:?} is on {origin:?}, not the issuer's own origin {issuer:?}; \
         refusing to treat it as part of this authorization server"
    )]
    EndpointOffOrigin {
        /// The metadata field.
        field: String,
        /// Its value.
        url: String,
        /// Its origin.
        origin: String,
        /// The issuer.
        issuer: String,
    },
    /// The authorization server does not list the PDS among its protected
    /// resources.
    #[error("PDS {pds_origin:?} is not listed in the authorization server's protected_resources")]
    PdsNotProtected {
        /// The PDS's origin.
        pds_origin: String,
    },
}

/// Why the authorization callback was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CallbackError {
    /// A JARM `response`, which is not supported.
    #[error("authorization response uses JARM, which is not supported")]
    Jarm,
    /// No `state`.
    #[error("authorization response carries no `state`")]
    NoState,
    /// No pending login holds this `state`: unknown, expired, or already used.
    #[error("no pending login for that `state` (unknown, expired, or already used)")]
    NoPendingLogin,
    /// **The browser binding.** The callback did not present this login's
    /// browser-binding cookie: another browser (a login CSRF), or a lost
    /// cookie. The pending login was consumed.
    #[error(
        "the callback did not present the browser-binding cookie for this login; \
         refusing to complete a flow this browser did not start"
    )]
    BindingMismatch,
    /// No `iss` (RFC 9207), which atproto requires.
    #[error("authorization response carries no `iss` (RFC 9207); refusing it")]
    NoIssuerParameter,
    /// **The mix-up defence at the callback.** `iss` is not the issuer the
    /// login was pushed to.
    #[error("authorization response `iss` is {got:?}, expected {expected:?}")]
    IssuerParameterMismatch {
        /// The `iss` presented.
        got: String,
        /// The login's issuer.
        expected: String,
    },
    /// The authorization server answered with an OAuth error. The code is
    /// reduced to a known slug ([`crate::flow::known_error_slug`]):
    /// `access_denied` is the user declining.
    #[error("authorization server returned error {0:?}")]
    ServerError(&'static str),
    /// No `code`.
    #[error("authorization response carries no `code`")]
    NoCode,
}

/// Which grant a token request was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Grant {
    /// The authorization-code exchange of a login.
    Authorization,
    /// A refresh.
    Refresh,
}

/// Why a token-endpoint (or PAR) request failed or was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The pushed authorization request was answered non-2xx.
    #[error("the pushed authorization request failed with status {status}")]
    ParFailed {
        /// Its status.
        status: u16,
    },
    /// The code exchange was answered non-2xx.
    #[error("the token exchange failed with status {status}")]
    ExchangeFailed {
        /// Its status.
        status: u16,
    },
    /// **The `sub` check.** The tokens are for another account than the one
    /// the login was started for (or the session belongs to); nothing was
    /// stored.
    #[error("{}", subject_mismatch_message(expected, returned, *during))]
    SubjectMismatch {
        /// The DID expected.
        expected: String,
        /// The `sub` the server returned.
        returned: String,
        /// Which request.
        during: Grant,
    },
}

/// When a session was found missing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionGone {
    /// There was none to begin with.
    Absent,
    /// It went while this call waited for another refresh of it.
    WhileWaitingToRefresh,
    /// It was signed out while this call refreshed it: the new tokens were not
    /// stored (and, if `revoked`, were revoked).
    SignedOutWhileRefreshing {
        /// Whether the new tokens were revoked.
        revoked: bool,
    },
}

/// Why a revocation request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevokeError {
    /// The authorization server advertises no revocation endpoint.
    #[error("the authorization server advertises no revocation endpoint")]
    NoEndpoint,
    /// `private_key_jwt` with no client signing key to sign the assertion.
    #[error("private_key_jwt requires the client signing key")]
    NoClientKey,
    /// The endpoint answered non-2xx.
    #[error("the revocation endpoint returned status {status}")]
    Status {
        /// Its status.
        status: u16,
    },
}

fn ssrf_message(host: &str, ip: &IpAddr) -> String {
    if host.parse::<IpAddr>().ok().as_ref() == Some(ip) {
        format!("refusing to fetch forbidden (internal) address {ip}")
    } else {
        format!("refusing to fetch {host:?}: resolves to forbidden address {ip}")
    }
}

fn redirect_message(status: u16, url: &str, refusal: &RedirectRefusal) -> String {
    // As `reqwest::StatusCode` renders: "302 Found".
    let status = match reqwest::StatusCode::from_u16(status) {
        Ok(code) => code.to_string(),
        Err(_) => status.to_string(),
    };
    match refusal {
        RedirectRefusal::NotFollowed => format!(
            "refusing to follow a {status} redirect while fetching {url:?} \u{2014} \
             this document's origin is load-bearing and must not be moved"
        ),
        RedirectRefusal::NoSingleTarget => format!(
            "refusing to act on a {status} response while fetching {url:?} \u{2014} \
             it names no single target that can be followed safely"
        ),
        RedirectRefusal::OnPost { location } => format!(
            "refusing to follow a {status} redirect on a POST to {url:?} (Location: {location}) \
             \u{2014} a 307/308 would re-send the request body to the new host"
        ),
    }
}

fn refresh_message(failure: RefreshFailure, sub: &str, status: u16) -> String {
    match failure {
        RefreshFailure::Transient => {
            format!("refresh for {sub} failed transiently (status {status}); the session is left intact")
        }
        RefreshFailure::SessionInvalid => format!(
            "refresh for {sub} was rejected as invalid_grant; the session has been \
             removed and the user must log in again"
        ),
    }
}

fn no_session_message(sub: &str, gone: &SessionGone) -> String {
    match gone {
        SessionGone::Absent => format!("no session for {sub}"),
        SessionGone::WhileWaitingToRefresh => {
            format!("session for {sub} disappeared while waiting to refresh")
        }
        SessionGone::SignedOutWhileRefreshing { revoked } => format!(
            "no session for {sub}: it was signed out while being refreshed (the new tokens were \
             not stored{})",
            if *revoked { ", and were revoked" } else { "" }
        ),
    }
}

fn subject_mismatch_message(expected: &str, returned: &str, during: Grant) -> String {
    match during {
        // Names neither DID, as the message always has.
        Grant::Authorization => "the authorization server returned tokens for a different \
                                 subject than the login was started for"
            .to_string(),
        Grant::Refresh => format!(
            "refresh returned subject {returned:?}, expected {expected:?}; refusing to rebind \
             the session"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every variant renders the message its `bail!` did**, including those
    /// no caller matches on today: each expected string is the old format
    /// string, filled in by hand.
    #[test]
    fn every_display_is_the_message_it_replaced() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        let handle = |problem| {
            Error::from(ResolutionError::InvalidHandle {
                handle: "Bad_Handle".into(),
                problem,
            })
        };
        let cases: Vec<(Error, &str)> = vec![
            (
                Error::Ssrf { host: "10.0.0.1".into(), ip: v4 },
                "refusing to fetch forbidden (internal) address 10.0.0.1",
            ),
            (
                Error::Ssrf { host: "::1".into(), ip: v6 },
                "refusing to fetch forbidden (internal) address ::1",
            ),
            (
                Error::Ssrf { host: "internal.test".into(), ip: v4 },
                "refusing to fetch \"internal.test\": resolves to forbidden address 10.0.0.1",
            ),
            (
                Error::RedirectRefused {
                    status: 302,
                    url: "https://a.test/x".into(),
                    refusal: RedirectRefusal::NotFollowed,
                },
                "refusing to follow a 302 Found redirect while fetching \"https://a.test/x\" \
                 \u{2014} this document's origin is load-bearing and must not be moved",
            ),
            (
                Error::RedirectRefused {
                    status: 305,
                    url: "https://a.test/x".into(),
                    refusal: RedirectRefusal::NoSingleTarget,
                },
                "refusing to act on a 305 Use Proxy response while fetching \"https://a.test/x\" \
                 \u{2014} it names no single target that can be followed safely",
            ),
            (
                Error::RedirectRefused {
                    status: 307,
                    url: "https://a.test/x".into(),
                    refusal: RedirectRefusal::OnPost {
                        location: "<none>".into(),
                    },
                },
                "refusing to follow a 307 Temporary Redirect redirect on a POST to \
                 \"https://a.test/x\" (Location: <none>) \u{2014} a 307/308 would re-send the \
                 request body to the new host",
            ),
            (
                handle(HandleProblem::InvalidLength),
                "handle \"Bad_Handle\" has an invalid length",
            ),
            (
                handle(HandleProblem::TooFewSegments),
                "handle \"Bad_Handle\" must have at least two segments",
            ),
            (
                handle(HandleProblem::SegmentLength),
                "handle \"Bad_Handle\" has an empty or over-long segment",
            ),
            (
                handle(HandleProblem::IllegalCharacters),
                "handle \"Bad_Handle\" has a segment with illegal characters",
            ),
            (
                handle(HandleProblem::EdgeHyphen),
                "handle \"Bad_Handle\" has a segment starting or ending with a hyphen",
            ),
            (
                handle(HandleProblem::NumericTld),
                "handle \"Bad_Handle\" has a TLD starting with a digit",
            ),
            (
                handle(HandleProblem::ReservedTld("local".into())),
                "handle \"Bad_Handle\" uses the reserved TLD .local",
            ),
            (
                ResolutionError::UnsupportedDidMethod { did: "did:key:z".into() }.into(),
                "unsupported DID method in \"did:key:z\"; only did:plc and did:web are resolvable",
            ),
            (
                ResolutionError::DidDocumentMismatch {
                    id: "did:plc:b".into(),
                    expected: "did:plc:a".into(),
                }
                .into(),
                "DID document id \"did:plc:b\" does not match the requested DID \"did:plc:a\"",
            ),
            (
                ResolutionError::NoPds { did: "did:plc:a".into() }.into(),
                "DID document declares no #atproto_pds service for did:plc:a",
            ),
            (
                ResolutionError::NoClaimedHandle.into(),
                "DID document claims no handle; cannot verify bidirectionally",
            ),
            (
                ResolutionError::HandleMismatch {
                    claimed: "b.test".into(),
                    wanted: "a.test".into(),
                }
                .into(),
                "DID document claims handle \"b.test\", not \"a.test\"",
            ),
            (
                DiscoveryError::IssuerMismatch {
                    discovered: "https://b".into(),
                    expected: "https://a".into(),
                }
                .into(),
                "the PDS now names a different authorization server (\"https://b\") than this \
                 grant was issued by (\"https://a\"); refusing to send credentials to it",
            ),
            (
                DiscoveryError::MetadataIssuerMismatch {
                    declared: "https://b".into(),
                    fetched: "https://a".into(),
                }
                .into(),
                "authorization-server declares issuer \"https://b\" but was fetched from \"https://a\"",
            ),
            (
                DiscoveryError::EndpointOffOrigin {
                    field: "token_endpoint".into(),
                    url: "https://b/t".into(),
                    origin: "https://b".into(),
                    issuer: "https://a".into(),
                }
                .into(),
                "`token_endpoint` \"https://b/t\" is on \"https://b\", not the issuer's own origin \
                 \"https://a\"; refusing to treat it as part of this authorization server",
            ),
            (
                DiscoveryError::PdsNotProtected { pds_origin: "https://p".into() }.into(),
                "PDS \"https://p\" is not listed in the authorization server's protected_resources",
            ),
            (
                CallbackError::Jarm.into(),
                "authorization response uses JARM, which is not supported",
            ),
            (
                CallbackError::NoState.into(),
                "authorization response carries no `state`",
            ),
            (
                CallbackError::NoPendingLogin.into(),
                "no pending login for that `state` (unknown, expired, or already used)",
            ),
            (
                CallbackError::BindingMismatch.into(),
                "the callback did not present the browser-binding cookie for this login; \
                 refusing to complete a flow this browser did not start",
            ),
            (
                CallbackError::NoIssuerParameter.into(),
                "authorization response carries no `iss` (RFC 9207); refusing it",
            ),
            (
                CallbackError::IssuerParameterMismatch {
                    got: "https://b".into(),
                    expected: "https://a".into(),
                }
                .into(),
                "authorization response `iss` is \"https://b\", expected \"https://a\"",
            ),
            (
                CallbackError::ServerError("access_denied").into(),
                "authorization server returned error \"access_denied\"",
            ),
            (
                CallbackError::NoCode.into(),
                "authorization response carries no `code`",
            ),
            (
                TokenError::ParFailed { status: 400 }.into(),
                "the pushed authorization request failed with status 400",
            ),
            (
                TokenError::ExchangeFailed { status: 401 }.into(),
                "the token exchange failed with status 401",
            ),
            (
                TokenError::SubjectMismatch {
                    expected: "did:plc:a".into(),
                    returned: "did:plc:b".into(),
                    during: Grant::Authorization,
                }
                .into(),
                "the authorization server returned tokens for a different subject than the \
                 login was started for",
            ),
            (
                TokenError::SubjectMismatch {
                    expected: "did:plc:a".into(),
                    returned: "did:plc:b".into(),
                    during: Grant::Refresh,
                }
                .into(),
                "refresh returned subject \"did:plc:b\", expected \"did:plc:a\"; refusing to \
                 rebind the session",
            ),
            (
                Error::Refresh {
                    failure: RefreshFailure::Transient,
                    sub: "did:plc:a".into(),
                    status: 503,
                },
                "refresh for did:plc:a failed transiently (status 503); the session is left intact",
            ),
            (
                Error::Refresh {
                    failure: RefreshFailure::SessionInvalid,
                    sub: "did:plc:a".into(),
                    status: 400,
                },
                "refresh for did:plc:a was rejected as invalid_grant; the session has been \
                 removed and the user must log in again",
            ),
            (
                Error::NoSession { sub: "did:plc:a".into(), gone: SessionGone::Absent },
                "no session for did:plc:a",
            ),
            (
                Error::NoSession {
                    sub: "did:plc:a".into(),
                    gone: SessionGone::WhileWaitingToRefresh,
                },
                "session for did:plc:a disappeared while waiting to refresh",
            ),
            (
                Error::NoSession {
                    sub: "did:plc:a".into(),
                    gone: SessionGone::SignedOutWhileRefreshing { revoked: false },
                },
                "no session for did:plc:a: it was signed out while being refreshed (the new \
                 tokens were not stored)",
            ),
            (
                Error::NoSession {
                    sub: "did:plc:a".into(),
                    gone: SessionGone::SignedOutWhileRefreshing { revoked: true },
                },
                "no session for did:plc:a: it was signed out while being refreshed (the new \
                 tokens were not stored, and were revoked)",
            ),
            (
                RevokeError::NoEndpoint.into(),
                "the authorization server advertises no revocation endpoint",
            ),
            (
                RevokeError::NoClientKey.into(),
                "private_key_jwt requires the client signing key",
            ),
            (
                RevokeError::Status { status: 500 }.into(),
                "the revocation endpoint returned status 500",
            ),
        ];
        for (err, want) in cases {
            assert_eq!(err.to_string(), want, "{err:?}");
            // No source of its own, so `{:#}` through anyhow adds nothing.
            let any = anyhow::Error::from(err);
            assert_eq!(format!("{any:#}"), want);
            assert_eq!(any.chain().count(), 1, "{want}");
        }
    }

    /// `Other` is the whole error, context and chain.
    #[test]
    fn other_renders_its_whole_chain() {
        let err = anyhow::anyhow!("inner").context("outer");
        let converted = Error::from(err);
        assert!(matches!(converted, Error::Other(_)));
        assert_eq!(format!("{converted:#}"), "outer: inner");
        assert_eq!(converted.to_string(), "outer");
    }
}
