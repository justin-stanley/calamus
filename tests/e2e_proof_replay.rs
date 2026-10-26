//! **The client never replays a DPoP proof.** The fake refuses any `jti` it
//! has seen before, on any host; a login, a refresh, a resource call (with
//! the `xrpc` feature) and a sign-out (with `revoke`), all through nonce
//! challenges, complete without one refusal.

mod common;

use std::collections::HashSet;

use calamus::session::{valid_session, RefreshLocks};
use calamus::testing::fake::{NoncePolicy, AS_HOST};
use common::{World, NOW};

#[tokio::test]
async fn the_client_never_replays_a_dpop_proof() {
    let w = World::new().await;
    let started = w.start(calamus::testing::fake::HANDLE).await.unwrap();
    let params = w.fake.approve(&started.authorize_url).unwrap();
    // Stale nonces at every step from here: each one is a retry, which is
    // where a proof would be resent if it ever were.
    w.fake.rotate_nonces();
    let login = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect("the login completes");

    w.fake.rotate_nonces();
    let server = w.discover_for(&login.session).await.unwrap();
    let session = valid_session(
        &w.sessions,
        &w.fetcher,
        &w.nonces,
        &RefreshLocks::default(),
        &login.did,
        &w.refresh_context(&server),
        NOW + 4000,
    )
    .await
    .expect("the refresh completes");

    #[cfg(feature = "xrpc")]
    {
        let key = calamus::keys::SigningKey::from_jwk_json(&session.dpop_key_jwk, "s").unwrap();
        let repo = calamus::xrpc::Repo {
            fetcher: &w.fetcher,
            nonces: &w.nonces,
            session: &session,
            key: &key,
        };
        repo.get("com.atproto.server.getSession", &[], NOW + 4000)
            .await
            .expect("the resource call completes");
    }
    #[cfg(feature = "revoke")]
    {
        w.fake.rotate_nonces();
        let ctx = calamus::revoke::RevokeContext {
            revocation_endpoint: server.revocation_endpoint.as_deref(),
            client_id: w.client.client_id(),
            auth_method: w.client.auth_method(),
            client_key: w.client.key(),
            deadline: calamus::revoke::REVOKE_DEADLINE,
            issuer: &server.issuer,
        };
        let outcome = calamus::revoke::sign_out(
            &w.sessions,
            &w.fetcher,
            &w.nonces,
            &ctx,
            &login.did,
            NOW + 4000,
        )
        .await;
        assert_eq!(outcome, calamus::revoke::Revocation::Revoked);
    }
    let _ = session;

    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
    let jtis: Vec<String> = w
        .fake
        .requests()
        .iter()
        .filter_map(|r| r.dpop_claims())
        .map(|c| c["jti"].as_str().unwrap().to_string())
        .collect();
    let unique: HashSet<&String> = jtis.iter().collect();
    assert_eq!(unique.len(), jtis.len(), "a jti was sent twice");
    let challenges = w
        .fake
        .refusals()
        .iter()
        .filter(|r| r.contains("use_dpop_nonce"))
        .count();
    assert!(challenges >= 3, "the retries were exercised: {challenges}");
}

/// **Negative control: the fake refuses a replayed proof.** The exact bytes
/// of a request it accepted, sent again, are `invalid_dpop_proof`.
#[tokio::test]
async fn the_fake_refuses_a_replayed_proof() {
    let w = World::with(|c| c.as_nonces = NoncePolicy::Never).await;
    w.login().await;
    let accepted = w
        .fake
        .requests_to(AS_HOST, "/par")
        .into_iter()
        .find(|r| r.status == 201)
        .expect("an accepted push");
    let proof = accepted.header("dpop").unwrap().to_string();
    let form = accepted.form();
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let resp = w
        .fetcher
        .post_form(
            &format!("{}/par", w.fake.issuer()),
            &[(
                reqwest::header::HeaderName::from_static("dpop"),
                reqwest::header::HeaderValue::from_str(&proof).unwrap(),
            )],
            &form,
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let refusal = w.fake.rejections().pop().unwrap_or_default();
    assert!(
        refusal.contains("invalid_dpop_proof") && refusal.contains("jti"),
        "{refusal}"
    );
}
