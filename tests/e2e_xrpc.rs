//! **Resource requests, end to end**: `xrpc::Repo` against the fake PDS as a
//! DPoP resource server. Needs the `xrpc` feature.

mod common;

use calamus::keys::SigningKey;
use calamus::testing::fake::{NoncePolicy, PDS_HOST};
use calamus::xrpc::Repo;
use common::{World, NOW};
use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION};

const NSID: &str = "com.atproto.repo.describeRepo";

/// **The PDS's header nonce challenge is answered once**: a 401 with
/// `WWW-Authenticate: DPoP error="use_dpop_nonce"`, then the retry with the
/// nonce succeeds, its proof bound to the access token (`ath`).
#[tokio::test]
async fn a_resource_request_answers_the_header_nonce_challenge_once() {
    let w = World::new().await;
    let login = w.login().await;
    let key = SigningKey::from_jwk_json(&login.session.dpop_key_jwk, "session").unwrap();
    let repo = Repo {
        fetcher: &w.fetcher,
        nonces: &w.nonces,
        session: &login.session,
        key: &key,
    };
    let did = login.did.clone();
    let got = repo
        .get(NSID, &[("repo", did.as_str())], NOW)
        .await
        .expect("the call succeeds after one challenge");
    let body: serde_json::Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(body["did"], login.did, "the PDS saw the session's token");

    let seen = w.fake.requests_to(PDS_HOST, &format!("/xrpc/{NSID}"));
    let statuses: Vec<u16> = seen.iter().map(|s| s.status).collect();
    assert_eq!(statuses, [401, 200], "one challenge, one retry");
    assert!(seen[0]
        .refusal
        .as_deref()
        .unwrap()
        .contains("use_dpop_nonce"));
    assert!(seen[0].dpop_claims().unwrap().get("nonce").is_none());
    assert!(seen[1].dpop_claims().unwrap()["nonce"].is_string());

    // And the next call carries the nonce from the start.
    repo.post_json("com.atproto.repo.createRecord", &serde_json::json!({}), NOW)
        .await
        .expect("a second call");
    let posts = w
        .fake
        .requests_to(PDS_HOST, "/xrpc/com.atproto.repo.createRecord");
    assert_eq!(posts.len(), 1, "no challenge the second time");
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// What a hand-built resource request changes from a correct one.
#[derive(Debug, Clone, Copy)]
enum Tamper {
    Nothing,
    NoAth,
    AnotherKey,
}

/// Send one resource request by hand (no nonces in this world).
async fn by_hand(w: &World, session: &calamus::store::Session, tamper: Tamper) -> u16 {
    let url = format!("{}/xrpc/{NSID}", session.aud);
    let other = SigningKey::generate("other");
    let own = SigningKey::from_jwk_json(&session.dpop_key_jwk, "session").unwrap();
    let key = match tamper {
        Tamper::AnotherKey => &other,
        _ => &own,
    };
    let ath = match tamper {
        Tamper::NoAth => None,
        _ => Some(session.access_token.as_str()),
    };
    let proof = calamus::dpop::proof(key, "GET", &url, ath, None, NOW).unwrap();
    let resp = w
        .fetcher
        .get_no_redirect(
            &url,
            &[
                (
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("DPoP {}", session.access_token)).unwrap(),
                ),
                (
                    HeaderName::from_static("dpop"),
                    HeaderValue::from_str(&proof).unwrap(),
                ),
            ],
        )
        .await
        .expect("answered");
    resp.status().as_u16()
}

/// **Negative control: the fake PDS checks `ath`.** A proof that does not
/// bind the access token is refused, as is one under a key the token was not
/// issued to; the same request done right is accepted.
#[tokio::test]
async fn a_proof_without_ath_is_rejected_by_the_pds() {
    let w = World::with(|c| {
        c.as_nonces = NoncePolicy::Never;
        c.pds_nonces = NoncePolicy::Never;
    })
    .await;
    let login = w.login().await;

    assert_eq!(by_hand(&w, &login.session, Tamper::NoAth).await, 401);
    let refusal = w.fake.rejections().pop().unwrap_or_default();
    assert!(
        refusal.contains("ath"),
        "refused, but not for ath: {refusal}"
    );

    assert_eq!(by_hand(&w, &login.session, Tamper::AnotherKey).await, 401);
    let refusal = w.fake.rejections().pop().unwrap_or_default();
    assert!(refusal.contains("DPoP key"), "{refusal}");

    assert_eq!(
        by_hand(&w, &login.session, Tamper::Nothing).await,
        200,
        "the control: done right, the same request is accepted"
    );
}
