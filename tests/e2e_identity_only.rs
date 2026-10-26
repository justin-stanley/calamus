//! **The identity-only flow** ("sign in with atproto", Rubrica's use): a
//! confidential client asking for the bare `atproto` scope with an inline
//! JWKS, keeping no tokens (`store::Discard`), end to end against the fake.

mod common;

use calamus::login::{CompletedLogin, Deps};
use calamus::store::Discard;
use calamus::testing::fake::{AS_HOST, HANDLE};
use common::{World, NOW};

/// One identity-only login; the fake answers the exchange with `sub` when
/// given.
async fn identity_login(sub: Option<&str>) -> (World, anyhow::Result<CompletedLogin>) {
    let w = World::build("atproto", |_| {}).await;
    w.fake.set_sub(sub);
    let deps = Deps {
        fetcher: &w.fetcher,
        dns: &w.dns,
        pending: &w.pending,
        sessions: &Discard,
        nonces: &w.nonces,
    };
    let started = w.client.start(&deps, HANDLE, NOW).await.expect("it starts");
    let params = w.fake.approve(&started.authorize_url).unwrap();
    let done = w
        .client
        .complete(&deps, &params, Some(&started.binding_token), NOW)
        .await;
    (w, done)
}

/// **The `sub` is verified and no token is kept.** PAR asked for exactly
/// `atproto`; the DID handed back is the resolved one; nothing holds the
/// tokens afterwards; and the published metadata embeds its keys rather than
/// pointing at them.
#[tokio::test]
async fn an_identity_only_client_verifies_sub_and_keeps_no_tokens() {
    let (w, done) = identity_login(None).await;
    let done = done.expect("the identity-only login completes");
    assert_eq!(done.did, w.fake.did());
    assert_eq!(done.handle.as_deref(), Some(HANDLE));

    let pushed = w.fake.pushed();
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].scope, "atproto", "PAR asked for exactly atproto");

    use calamus::store::SessionStore;
    assert!(
        Discard.get(&done.did).await.unwrap().is_none(),
        "nothing is kept"
    );
    assert!(w.sessions.get(&done.did).await.unwrap().is_none());

    let document = w.client.metadata().document();
    assert!(document.get("jwks").is_some(), "{document}");
    assert!(document.get("jwks_uri").is_none(), "{document}");
    assert_eq!(document["scope"], "atproto");
}

/// **The `sub` check holds with no store behind it**: tokens for another DID
/// are refused, not handed back.
#[tokio::test]
async fn an_identity_only_client_still_refuses_a_sub_mismatch() {
    let (w, done) = identity_login(Some("did:plc:someoneelseaaaaaaaaaaaaa")).await;
    let err = done.expect_err("a sub mismatch must be refused");
    assert!(format!("{err:#}").contains("different subject"), "{err:#}");
    assert_eq!(w.fake.count(AS_HOST, "/token"), 1, "the exchange happened");
}
