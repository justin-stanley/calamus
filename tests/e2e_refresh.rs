//! **Keeping a session valid, end to end**: `session::valid_session` against
//! the fake authorization server's refresh grant (single use, rotating).

mod common;

use std::time::Duration;

use calamus::session::{valid_session, RefreshLocks};
use calamus::store::SessionStore;
use calamus::testing::fake::{AS_HOST, OTHER_AS_HOST};
use common::{World, NOW};

/// Late enough that a fresh login's session is stale.
const LATER: i64 = NOW + 4000;

/// **A stale session is refreshed, and both tokens rotate.** The stored row
/// is the new grant, and the refresh went out under the session's own key.
#[tokio::test]
async fn a_stale_session_is_refreshed_and_rotated() {
    let w = World::new().await;
    let login = w.login().await;
    let server = w.discover_for(&login.session).await.unwrap();
    let locks = RefreshLocks::default();

    let fresh = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &locks,
        &login.did,
        &w.refresh_context(&server),
        LATER,
    )
    .await
    .expect("the refresh succeeds");

    let issued = w.fake.issued();
    assert_eq!(issued.len(), 2, "the login's tokens, then the refresh's");
    assert!(issued[0].refresh_used, "the old refresh token was spent");
    assert_eq!(fresh.access_token, issued[1].access_token);
    assert_eq!(fresh.refresh_token, issued[1].refresh_token);
    assert_ne!(fresh.refresh_token, login.session.refresh_token);
    assert_eq!(fresh.expires_at, Some(LATER + 3600));
    assert_eq!(fresh.dpop_key_jwk, login.session.dpop_key_jwk);
    assert_eq!(issued[1].dpop_jkt, issued[0].dpop_jkt, "the same key");
    assert_eq!(w.sessions.get(&login.did).await.unwrap(), Some(fresh));
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// **A refresh token used twice is `invalid_grant`**, and the session that
/// presented it is removed: the grant is dead and the user must log in again.
#[tokio::test]
async fn a_second_use_of_a_refresh_token_is_invalid_grant_and_removes_the_session() {
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

    // A stale copy (a restored backup, another process's cache) presents the
    // spent token again.
    w.sessions.put(&login.session).await.unwrap();
    let err = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &locks,
        &login.did,
        &ctx,
        LATER,
    )
    .await
    .expect_err("a spent refresh token must fail");
    assert!(format!("{err:#}").contains("invalid_grant"), "{err:#}");

    let last = w.fake.requests_to(AS_HOST, "/token").pop().unwrap();
    assert_eq!(last.status, 400);
    assert!(
        last.refusal
            .as_deref()
            .unwrap_or_default()
            .contains("invalid_grant"),
        "{:?}",
        last.refusal
    );
    assert!(
        w.sessions.get(&login.did).await.unwrap().is_none(),
        "removed"
    );
}

/// **A 5xx on refresh leaves the session exactly as it was.**
#[tokio::test]
async fn a_5xx_on_refresh_leaves_the_session_intact() {
    let w = World::new().await;
    let login = w.login().await;
    let server = w.discover_for(&login.session).await.unwrap();
    w.fake.fail_next_with(503);
    let err = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &RefreshLocks::default(),
        &login.did,
        &w.refresh_context(&server),
        LATER,
    )
    .await
    .expect_err("a 503 fails this request");
    assert!(format!("{err:#}").contains("transiently"), "{err:#}");
    assert_eq!(
        w.sessions.get(&login.did).await.unwrap(),
        Some(login.session),
        "the session is untouched"
    );
}

/// **A refresh is never sent to an issuer the session does not belong to.**
/// The PDS now names another authorization server: discovery for the
/// session's issuer refuses it, and a context built from the new server's
/// discovery is refused by the refresh itself. No token request either way.
#[tokio::test]
async fn a_refresh_to_a_moved_issuer_is_refused() {
    let w = World::new().await;
    let login = w.login().await;
    w.fake.point_pds_at(OTHER_AS_HOST);

    let err = w
        .discover_for(&login.session)
        .await
        .expect_err("discovery for the session's issuer must refuse a moved PDS");
    assert!(
        format!("{err:#}").contains("different authorization server"),
        "{err:#}"
    );

    // A caller that discovered without expecting an issuer gets the new
    // server's endpoints; the refresh compares the session's issuer.
    let moved = calamus::discovery::discover(
        &w.fetcher,
        &login.session.aud,
        w.client.auth_method().as_str(),
        None,
    )
    .await
    .expect("the moved server's own metadata is consistent");
    let err = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &RefreshLocks::default(),
        &login.did,
        &w.refresh_context(&moved),
        LATER,
    )
    .await
    .expect_err("a refresh at another issuer must be refused");
    assert!(
        format!("{err:#}").contains("different authorization server"),
        "{err:#}"
    );
    assert_eq!(w.fake.count(OTHER_AS_HOST, "/token"), 0);
    assert_eq!(
        w.fake.count(AS_HOST, "/token"),
        1,
        "only the login's exchange"
    );
}

/// **Two concurrent refreshes of one subject make one token request.** The
/// server is slow, so without the lock both would read the stale row and
/// both present its single-use token.
#[tokio::test]
async fn concurrent_refreshes_of_one_subject_make_one_token_request() {
    let w = World::new().await;
    let login = w.login().await;
    let server = w.discover_for(&login.session).await.unwrap();
    let ctx = w.refresh_context(&server);
    let locks = RefreshLocks::default();
    w.fake.stall_next(Duration::from_millis(300));

    let one = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &locks,
        &login.did,
        &ctx,
        LATER,
    );
    let two = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &locks,
        &login.did,
        &ctx,
        LATER,
    );
    let (one, two) = tokio::join!(one, two);
    let (one, two) = (one.expect("first"), two.expect("second"));
    assert_eq!(one, two, "both callers get the one refreshed session");
    let refreshes = w
        .fake
        .requests_to(AS_HOST, "/token")
        .into_iter()
        .filter(|r| r.form_value("grant_type").as_deref() == Some("refresh_token"))
        .count();
    assert_eq!(refreshes, 1, "one refresh request");
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// **An absurd clock saturates the whole way through.** A `private_key_jwt`
/// login and then `valid_session` at `now = i64::MAX - 10`: every `now + secs`
/// (the pending row's expiry, the session's expiry, the client assertion's
/// `exp`, the staleness margin) saturates rather than panicking in a debug
/// build (or wrapping to the past in release). The stored expiry saturates at
/// `i64::MAX`, which the margin still counts as stale, so the session is
/// refreshed.
#[tokio::test]
async fn an_absurd_clock_saturates_through_login_and_valid_session() {
    const ABSURD: i64 = i64::MAX - 10;
    let w = World::new().await;
    assert_eq!(
        w.client.auth_method(),
        calamus::client_auth::AuthMethod::PrivateKeyJwt,
        "precondition: the assertion path is exercised"
    );
    let started = w
        .client
        .start(&w.deps(), calamus::testing::fake::HANDLE, ABSURD)
        .await
        .expect("the login starts");
    let params = w.fake.approve(&started.authorize_url).unwrap();
    let login = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), ABSURD)
        .await
        .expect("the login completes");
    assert_eq!(login.session.expires_at, Some(i64::MAX));

    let server = w.discover_for(&login.session).await.unwrap();
    let fresh = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &RefreshLocks::default(),
        &login.did,
        &w.refresh_context(&server),
        ABSURD,
    )
    .await
    .expect("valid_session at an absurd clock");
    assert_eq!(fresh.expires_at, Some(i64::MAX));
    assert_eq!(w.fake.issued().len(), 2, "the login, then the refresh");
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// **A refresh context carries the issuer of the discovery its endpoints came
/// from.** A caller that discovers without expecting the session's issuer,
/// after the PDS has been repointed, gets the new server: built with
/// `RefreshContext::new`, the context's issuer IS that server's, so the
/// refresh refuses the stored grant (another issuer's) before any request.
/// The old misuse (the new server's endpoints with the row's issuer, which
/// passed the check and sent the refresh token to whatever server the PDS
/// named) cannot be written: the fields are private.
#[tokio::test]
async fn a_context_from_a_discovery_at_another_issuer_refuses_before_any_request() {
    let w = World::new().await;
    let login = w.login().await;
    w.fake.point_pds_at(OTHER_AS_HOST);
    let moved = calamus::discovery::discover(
        &w.fetcher,
        &login.session.aud,
        w.client.auth_method().as_str(),
        None,
    )
    .await
    .expect("the moved server's own metadata is consistent");
    let ctx = calamus::session::RefreshContext::new(&moved, &w.client);
    assert_eq!(ctx.issuer(), moved.issuer);
    assert_eq!(ctx.token_endpoint(), moved.token_endpoint);
    assert_eq!(
        ctx.revocation_endpoint(),
        moved.revocation_endpoint.as_deref()
    );

    let err = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &RefreshLocks::default(),
        &login.did,
        &ctx,
        LATER,
    )
    .await
    .expect_err("another issuer's context must be refused");
    match calamus::Error::find(&err) {
        Some(calamus::Error::Discovery(calamus::error::DiscoveryError::IssuerMismatch {
            discovered,
            expected,
            ..
        })) => {
            assert_eq!(discovered, &moved.issuer);
            assert_eq!(expected, &login.session.issuer);
        }
        other => panic!("{other:?}: {err:#}"),
    }
    assert_eq!(w.fake.count(OTHER_AS_HOST, "/token"), 0);
    assert_eq!(w.fake.count(AS_HOST, "/token"), 1, "only the login's");
    assert_eq!(
        w.sessions.get(&login.did).await.unwrap(),
        Some(login.session)
    );
}
