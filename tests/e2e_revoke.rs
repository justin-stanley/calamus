//! **Signing out, end to end**: `revoke::sign_out` against the fake
//! authorization server's `/revoke`. Needs the `revoke` feature.

mod common;

use std::time::{Duration, Instant};

use calamus::revoke::{sign_out, Revocation, RevokeContext, REVOKE_DEADLINE};
use calamus::store::SessionStore;
use calamus::testing::fake::{AS_HOST, OTHER_AS_HOST};
use common::{session_jkt, World, NOW};

fn context<'a>(
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

/// **Sign-out presents the refresh token, proved with the session's own DPoP
/// key, and deletes the row.** The grant is then dead at the server: its
/// access token no longer works at the PDS... and its refresh token no
/// longer refreshes.
#[tokio::test]
async fn sign_out_presents_the_refresh_token_with_the_sessions_dpop_key_and_deletes_the_row() {
    let w = World::new().await;
    let login = w.login().await;
    let server = w.discover_for(&login.session).await.unwrap();
    let ctx = context(
        &w,
        &server.issuer,
        server.revocation_endpoint.as_deref(),
        REVOKE_DEADLINE,
    );

    let outcome = sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await;
    assert_eq!(outcome, Revocation::Revoked);

    let revoked = w.fake.revoked();
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert_eq!(revoked[0].issuer_host, AS_HOST);
    assert_eq!(
        revoked[0].token, login.session.refresh_token,
        "the refresh token"
    );
    assert_eq!(
        revoked[0].dpop_jkt.as_deref(),
        Some(session_jkt(&login.session).as_str()),
        "proved with the session's DPoP key"
    );
    assert!(
        w.sessions.get(&login.did).await.unwrap().is_none(),
        "deleted"
    );
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// **No revocation endpoint: the row is deleted anyway**, and the outcome
/// says the server was not told.
#[tokio::test]
async fn sign_out_with_no_revocation_endpoint_still_deletes() {
    let w = World::new().await;
    w.fake.advertise_revocation(false);
    let login = w.login().await;
    let server = w.discover_for(&login.session).await.unwrap();
    assert_eq!(server.revocation_endpoint, None);
    let ctx = context(&w, &server.issuer, None, REVOKE_DEADLINE);

    let outcome = sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await;
    assert!(matches!(outcome, Revocation::Failed(_)), "{outcome:?}");
    assert!(
        w.sessions.get(&login.did).await.unwrap().is_none(),
        "deleted"
    );
    assert_eq!(w.fake.count(AS_HOST, "/revoke"), 0);
}

/// **A hanging authorization server does not hold the sign-out open**: past
/// the deadline the attempt is abandoned and the row goes.
#[tokio::test]
async fn a_hanging_server_does_not_hold_the_sign_out_open() {
    let w = World::new().await;
    let login = w.login().await;
    let server = w.discover_for(&login.session).await.unwrap();
    let ctx = context(
        &w,
        &server.issuer,
        server.revocation_endpoint.as_deref(),
        Duration::from_millis(300),
    );
    w.fake.stall_next(Duration::from_secs(30));

    let began = Instant::now();
    let outcome = sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await;
    let took = began.elapsed();
    assert!(matches!(outcome, Revocation::Failed(_)), "{outcome:?}");
    assert!(
        took < Duration::from_secs(5),
        "the sign-out waited {took:?}"
    );
    assert!(
        w.sessions.get(&login.did).await.unwrap().is_none(),
        "deleted"
    );
}

/// **A sign-out whose FIRST read is another issuer's row sends nothing and
/// leaves the row.** The PDS now names another authorization server, and a
/// caller that discovered without expecting the session's issuer holds that
/// server's endpoint. The stored grant belongs to the old server: its refresh
/// token must not reach the new one (which would answer 200 for a token it
/// does not know), and deleting the row would drop a live grant with no record
/// left to revoke it from. The outcome says it was left, not deleted.
#[tokio::test]
async fn a_sign_out_whose_first_read_is_another_issuers_row_sends_nothing_and_leaves_it() {
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
    assert_ne!(moved.issuer, login.session.issuer, "precondition");
    assert!(moved.revocation_endpoint.is_some(), "precondition");
    let ctx = context(
        &w,
        &moved.issuer,
        moved.revocation_endpoint.as_deref(),
        REVOKE_DEADLINE,
    );

    let outcome = sign_out(&w.sessions, &w.fetcher, &w.nonces, &ctx, &login.did, NOW).await;
    match &outcome {
        Revocation::LeftInPlace(reason) => assert!(
            reason.contains("different authorization server"),
            "{reason}"
        ),
        other => panic!("another issuer's row must be reported left in place: {other:?}"),
    }
    assert_eq!(
        w.fake.count_on_any_as("/revoke"),
        0,
        "a revocation was sent"
    );
    assert_eq!(
        w.sessions.get(&login.did).await.unwrap(),
        Some(login.session.clone()),
        "the other issuer's live grant was deleted unrevoked"
    );
}
