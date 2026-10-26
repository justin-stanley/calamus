//! **Logging in, end to end**, against the fake authorization server, PDS,
//! PLC directory and DNS (`calamus::testing::fake`): the real
//! `Client::start` and `Client::complete`, the real resolver, discovery,
//! SSRF-guarded fetcher and TLS validation, over loopback.

mod common;

use calamus::flow::CallbackParams;
use calamus::keys::SigningKey;
use calamus::store::{PendingLoginStore, SessionStore};
use calamus::testing::fake::{NoncePolicy, AS_HOST, EVIL_AS_HOST, HANDLE, PDS_HOST, PLC_HOST};
use calamus::testing::StaticDns;
use common::{session_jkt, World, NOW, REDIRECT, SCOPE};

/// **The whole flow from a handle.** Resolution by TXT (the well-known file is
/// never fetched), discovery, PAR under the session's key, the code exchange,
/// and a session bound to the resolved DID, the PDS and the issuer, carrying
/// exactly the tokens the server issued.
#[tokio::test]
async fn a_handle_login_stores_a_session_bound_to_the_resolved_did() {
    let w = World::new().await;
    let done = w.login().await;
    let did = w.fake.did();

    assert_eq!(done.did, did);
    assert_eq!(
        done.handle.as_deref(),
        Some(HANDLE),
        "the handle round-trips"
    );

    let pushed = w.fake.pushed();
    assert_eq!(pushed.len(), 1, "one push");
    let push = &pushed[0];
    assert_eq!(
        push.login_hint.as_deref(),
        Some(HANDLE),
        "PAR carried login_hint"
    );
    assert_eq!(push.scope, SCOPE);
    assert_eq!(push.redirect_uri, REDIRECT);

    let stored = w
        .sessions
        .get(&did)
        .await
        .unwrap()
        .expect("a session is stored");
    assert_eq!(stored, done.session, "what is returned is what is stored");
    assert_eq!(
        session_jkt(&stored),
        push.dpop_jkt,
        "the session's DPoP key is the one PAR was signed under"
    );
    assert_eq!(stored.aud, w.fake.pds_url(), "aud is the PDS");
    assert_eq!(
        stored.issuer,
        w.fake.issuer(),
        "issuer is the authorization server"
    );

    let issued = w.fake.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(stored.access_token, issued[0].access_token);
    assert_eq!(stored.refresh_token, issued[0].refresh_token);
    assert_eq!(stored.token_type, "DPoP");
    assert_eq!(stored.granted_scope, SCOPE);
    assert_eq!(stored.expires_at, Some(NOW + 3600));

    assert_eq!(
        w.fake.count(HANDLE, "/.well-known/atproto-did"),
        0,
        "DNS answered, so the well-known file is never fetched"
    );
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// **No TXT record: the handle resolves by its well-known file, fetched once.**
#[tokio::test]
async fn a_handle_without_a_txt_record_resolves_by_its_well_known_file() {
    let mut w = World::new().await;
    w.dns = StaticDns::new();
    let done = w.login().await;
    assert_eq!(done.did, w.fake.did());
    assert_eq!(done.handle.as_deref(), Some(HANDLE));
    // Once at start, and once more when complete re-resolves the handle from
    // the DID: each resolution fetches it exactly once.
    assert_eq!(w.fake.count(HANDLE, "/.well-known/atproto-did"), 2);
    assert_eq!(w.dns.queries().len(), 2, "{:?}", w.dns.queries());
}

/// **A did:web account logs in too**: its document comes from the host's own
/// `/.well-known/did.json`, and the PLC directory is never asked.
#[tokio::test]
async fn a_did_web_account_logs_in() {
    let w = World::with(|c| c.did_web = true).await;
    let done = w.login().await;
    assert_eq!(done.did, "did:web:alice-e2e.test");
    assert_eq!(done.handle.as_deref(), Some(HANDLE));
    assert!(w.fake.count(HANDLE, "/.well-known/did.json") >= 1);
    assert_eq!(
        w.fake
            .requests()
            .iter()
            .filter(|r| r.host == PLC_HOST)
            .count(),
        0
    );
}

/// **From a DID, a handle the DID document claims but that does not resolve
/// back is withheld.** The positive control: with the TXT record pointing
/// back, the same login reports the handle.
#[tokio::test]
async fn a_did_first_login_withholds_an_unverified_handle() {
    let mut w = World::new().await;
    let did = w.fake.did();
    // The handle's TXT names someone else.
    w.dns = StaticDns::new().with_txt(
        &format!("_atproto.{HANDLE}."),
        &[&["did=did:plc:someoneelseaaaaaaaaaaaaa"]],
    );
    let started = w.start(&did).await.expect("a DID-first login starts");
    let params = w.fake.approve(&started.authorize_url).unwrap();
    let done = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect("the login completes");
    assert_eq!(done.did, did);
    assert_eq!(done.handle, None, "an unverified handle is not reported");

    // Positive control.
    let w = World::new().await;
    let started = w.start(&w.fake.did()).await.unwrap();
    let params = w.fake.approve(&started.authorize_url).unwrap();
    let done = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .unwrap();
    assert_eq!(done.handle.as_deref(), Some(HANDLE));
}

/// **The `sub` check.** The authorization server answers the exchange with
/// another account's DID: the login fails and nothing is stored, under either
/// DID.
#[tokio::test]
async fn a_token_response_for_another_did_is_refused_and_nothing_is_stored() {
    let w = World::new().await;
    let other = "did:plc:someoneelseaaaaaaaaaaaaa";
    w.fake.set_sub(Some(other));
    let started = w.start(HANDLE).await.unwrap();
    let params = w.fake.approve(&started.authorize_url).unwrap();
    let err = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect_err("tokens for another DID must be refused");
    assert!(
        format!("{err:#}").contains("different subject"),
        "refused, but not by the sub check: {err:#}"
    );
    assert_eq!(
        w.fake.count(AS_HOST, "/token"),
        1,
        "the exchange did happen"
    );
    assert!(w.sessions.get(&w.fake.did()).await.unwrap().is_none());
    assert!(w.sessions.get(other).await.unwrap().is_none());
}

/// **A nonce challenge at PAR and at the token endpoint is answered once
/// each.** The first push carries no nonce; the exchange carries PAR's,
/// which has gone stale while the user approved.
#[tokio::test]
async fn a_nonce_challenge_at_par_and_at_token_is_retried_exactly_once_each() {
    let w = World::new().await;
    let started = w.start(HANDLE).await.unwrap();
    let params = w.fake.approve(&started.authorize_url).unwrap();
    w.fake.rotate_nonces();
    w.client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect("the login completes after both challenges");

    for path in ["/par", "/token"] {
        let seen = w.fake.requests_to(AS_HOST, path);
        let statuses: Vec<u16> = seen.iter().map(|s| s.status).collect();
        assert_eq!(
            statuses.len(),
            2,
            "{path}: one challenge, one retry: {statuses:?}"
        );
        assert_eq!(statuses[0], 400, "{path}: challenged first");
        assert!(
            seen[0]
                .refusal
                .as_deref()
                .unwrap_or_default()
                .contains("use_dpop_nonce"),
            "{path}: {:?}",
            seen[0].refusal
        );
        assert!((200..300).contains(&statuses[1]), "{path}: then accepted");
    }
    assert!(w.fake.rejections().is_empty(), "{:?}", w.fake.rejections());
}

/// **A callback claiming another issuer posts nothing anywhere** (RFC 9207).
#[tokio::test]
async fn the_callback_from_the_wrong_issuer_posts_nothing() {
    let w = World::new().await;
    let started = w.start(HANDLE).await.unwrap();
    let mut params = w.fake.approve(&started.authorize_url).unwrap();
    params.iss = Some(w.fake.origin(EVIL_AS_HOST));
    let err = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect_err("a callback from another issuer must be refused");
    assert!(format!("{err:#}").contains("`iss`"), "{err:#}");
    assert_eq!(w.fake.count_on_any_as("/token"), 0, "the code went nowhere");
    assert!(w.sessions.get(&w.fake.did()).await.unwrap().is_none());
}

/// **A browser without the binding cookie cannot complete the flow.**
#[tokio::test]
async fn a_foreign_browser_cannot_complete_the_flow() {
    let w = World::new().await;
    // A login per attempt: the first attempt consumes its pending row.
    for cookie in [None, Some("another-browsers-cookie")] {
        let started = w.start(HANDLE).await.unwrap();
        let params = w.fake.approve(&started.authorize_url).unwrap();
        let err = w
            .client
            .complete(&w.deps(), &params, cookie, NOW)
            .await
            .expect_err("a foreign browser must be refused");
        assert!(
            format!("{err:#}").contains("browser-binding cookie"),
            "{cookie:?}: refused, but not by the binding check: {err:#}"
        );
    }
    assert_eq!(w.fake.count_on_any_as("/token"), 0);
    assert!(w.sessions.get(&w.fake.did()).await.unwrap().is_none());
}

/// **The PDS now names another authorization server**: the callback's
/// re-discovery refuses it before the code, the verifier or an assertion is
/// posted to either server.
#[tokio::test]
async fn a_repointed_pds_is_refused_before_the_code_is_posted() {
    let w = World::new().await;
    let started = w.start(HANDLE).await.unwrap();
    let params = w.fake.approve(&started.authorize_url).unwrap();
    w.fake.point_pds_at(EVIL_AS_HOST);
    let err = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect_err("a repointed PDS must be refused");
    assert!(
        format!("{err:#}").contains("different authorization server"),
        "refused, but not by the mix-up check: {err:#}"
    );
    assert_eq!(w.fake.count_on_any_as("/token"), 0, "the code went nowhere");
}

/// **A callback replayed after a completed login is refused**, and posts
/// nothing: the pending login was consumed.
#[tokio::test]
async fn a_replayed_callback_is_refused() {
    let w = World::new().await;
    let started = w.start(HANDLE).await.unwrap();
    let params = w.fake.approve(&started.authorize_url).unwrap();
    w.client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect("the first callback completes");
    let err = w
        .client
        .complete(&w.deps(), &params, Some(&started.binding_token), NOW)
        .await
        .expect_err("a replayed callback must be refused");
    assert!(format!("{err:#}").contains("already used"), "{err:#}");
    assert_eq!(
        w.fake.count(AS_HOST, "/token"),
        1,
        "the replay posted nothing"
    );
}

/// **A DID document naming a PDS on a private address fails closed**, at the
/// SSRF guard, before any authorization server is contacted.
#[tokio::test]
async fn a_pds_on_a_private_address_fails_closed() {
    let w = World::new().await;
    w.fake.set_pds_endpoint("https://10.0.0.5");
    let err = w
        .start(HANDLE)
        .await
        .expect_err("a private PDS must be refused");
    assert!(
        format!("{err:#}").contains("forbidden (internal) address"),
        "refused, but not by the SSRF guard: {err:#}"
    );
    assert_eq!(w.fake.count_on_any_as("/par"), 0);
    assert!(w.fake.pushed().is_empty());
}

/// **A DID document served through a redirect is refused**, and the redirect
/// target is never fetched.
#[tokio::test]
async fn a_did_document_served_through_a_redirect_is_refused() {
    let w = World::new().await;
    w.fake.redirect_did_documents(true);
    let err = w
        .start(HANDLE)
        .await
        .expect_err("a redirected DID document must be refused");
    assert!(
        format!("{err:#}").contains("refusing to follow a 302"),
        "refused, but not by the no-redirect rule: {err:#}"
    );
    let moved: Vec<_> = w
        .fake
        .requests()
        .into_iter()
        .filter(|r| r.path.starts_with("/moved/"))
        .collect();
    assert!(moved.is_empty(), "the redirect was followed: {moved:?}");
    assert_eq!(w.fake.count(PLC_HOST, &format!("/{}", w.fake.did())), 1);
    assert_eq!(w.fake.count_on_any_as("/par"), 0);
}

// ── negative controls: the fake's own checks bite ───────────────────────────
//
// Each control sends ONE token request by hand that differs from a correct one
// in a single field, and asserts the fake refuses it for that reason; then
// sends the correct one and asserts it succeeds. Without these, every e2e pass
// above could be a fake that accepts anything.

/// What a hand-built token request changes from a correct one.
#[derive(Clone, Copy, Debug)]
enum Tamper {
    Nothing,
    CodeVerifier,
    DpopKey,
    DpopSignature,
    AssertionAudience,
}

/// Start and approve a login (no nonces, so a hand-built proof needs none),
/// then return a function that posts the exchange with `tamper` applied.
struct HandExchange {
    w: World,
    params: CallbackParams,
    verifier: String,
    key: SigningKey,
}

impl HandExchange {
    async fn new() -> Self {
        let w = World::with(|c| {
            c.as_nonces = NoncePolicy::Never;
            c.pds_nonces = NoncePolicy::Never;
        })
        .await;
        let started = w.start(HANDLE).await.unwrap();
        let params = w.fake.approve(&started.authorize_url).unwrap();
        let pending = w
            .pending
            .take(params.state.as_deref().unwrap(), NOW)
            .await
            .unwrap()
            .expect("the pending login");
        let key = SigningKey::from_jwk_json(&pending.dpop_key_jwk, "session").unwrap();
        Self {
            w,
            params,
            verifier: pending.pkce_verifier,
            key,
        }
    }

    /// Post the exchange; the status and the fake's refusal reason.
    async fn post(&self, tamper: Tamper) -> (u16, Option<String>) {
        let issuer = self.w.fake.issuer();
        let url = format!("{issuer}/token");
        let verifier = match tamper {
            Tamper::CodeVerifier => "a".repeat(43),
            _ => self.verifier.clone(),
        };
        let other = SigningKey::generate("other");
        let key = match tamper {
            Tamper::DpopKey => &other,
            _ => &self.key,
        };
        let mut proof = calamus::dpop::proof(key, "POST", &url, None, None, NOW).unwrap();
        if let Tamper::DpopSignature = tamper {
            // Re-sign the same header and claims under another key: the
            // embedded jwk no longer verifies the signature.
            let (head, rest) = proof.split_once('.').unwrap();
            let (claims, _) = rest.split_once('.').unwrap();
            let forged = calamus::dpop::proof(&other, "POST", &url, None, None, NOW).unwrap();
            let sig = forged.rsplit('.').next().unwrap();
            proof = format!("{head}.{claims}.{sig}");
        }
        let aud = match tamper {
            Tamper::AssertionAudience => self.w.fake.pds_url(),
            _ => issuer.clone(),
        };
        let assertion = calamus::client_auth::client_assertion(
            self.w.client.key().unwrap(),
            self.w.client.client_id(),
            &aud,
            NOW,
        )
        .unwrap();
        let form = [
            ("grant_type", "authorization_code"),
            ("code", self.params.code.as_deref().unwrap()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", verifier.as_str()),
            ("client_id", self.w.client.client_id()),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
        ];
        let resp = self
            .w
            .fetcher
            .post_form(
                &url,
                &[(
                    reqwest::header::HeaderName::from_static("dpop"),
                    reqwest::header::HeaderValue::from_str(&proof).unwrap(),
                )],
                &form,
            )
            .await
            .expect("the request is answered");
        let status = resp.status().as_u16();
        let refusal = self
            .w
            .fake
            .requests_to(AS_HOST, "/token")
            .last()
            .and_then(|s| s.refusal.clone());
        (status, refusal)
    }

    /// The tampered request is refused for `reason`, and the untampered one
    /// is then accepted.
    async fn assert_refused(tamper: Tamper, reason: &str) {
        let x = Self::new().await;
        let (status, refusal) = x.post(tamper).await;
        assert!(
            (400..500).contains(&status),
            "{tamper:?} was accepted ({status})"
        );
        let refusal = refusal.unwrap_or_default();
        assert!(
            refusal.contains(reason),
            "{tamper:?} was refused, but not for {reason:?}: {refusal}"
        );
        let (status, refusal) = x.post(Tamper::Nothing).await;
        assert_eq!(
            status, 200,
            "the control: the same request untampered must succeed ({refusal:?})"
        );
    }
}

/// **The fake checks PKCE**: a `code_verifier` whose S256 is not the pushed
/// challenge is `invalid_grant`.
#[tokio::test]
async fn the_fake_refuses_a_wrong_code_verifier() {
    HandExchange::assert_refused(Tamper::CodeVerifier, "code_verifier").await;
}

/// **The fake checks the grant's key binding**: an exchange signed under a
/// key other than PAR's is refused.
#[tokio::test]
async fn the_fake_refuses_an_exchange_under_another_dpop_key() {
    HandExchange::assert_refused(Tamper::DpopKey, "DPoP key").await;
}

/// **The fake verifies DPoP signatures**: a proof whose signature is not by
/// its embedded key is `invalid_dpop_proof`.
#[tokio::test]
async fn the_fake_refuses_a_forged_dpop_signature() {
    HandExchange::assert_refused(Tamper::DpopSignature, "signature").await;
}

/// **The fake checks the client assertion's audience**: one addressed to the
/// PDS rather than the issuer is `invalid_client`.
#[tokio::test]
async fn the_fake_refuses_an_assertion_for_another_audience() {
    HandExchange::assert_refused(Tamper::AssertionAudience, "aud").await;
}

/// The session the PDS host saw nothing of: discovery's only PDS request is
/// its protected-resource document.
#[tokio::test]
async fn a_login_asks_the_pds_only_for_its_protected_resource_document() {
    let w = World::new().await;
    w.login().await;
    let pds: Vec<String> = w
        .fake
        .requests()
        .into_iter()
        .filter(|r| r.host == PDS_HOST)
        .map(|r| r.path)
        .collect();
    assert!(
        pds.iter()
            .all(|p| p == "/.well-known/oauth-protected-resource"),
        "{pds:?}"
    );
}
