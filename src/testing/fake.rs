//! A stateful fake of the atproto world one login touches: the account's
//! handle (DNS and `/.well-known/atproto-did`), its DID document (did:plc
//! through a PLC directory, or did:web), its PDS (protected-resource metadata
//! and `/xrpc/*` as a DPoP resource server) and the PDS's authorization server
//! (metadata, PAR, token, refresh, revocation).
//!
//! **One TLS listener answers as every host**, told apart by the `Host`
//! header; [`Fake::fetcher`] is a [`Fetcher`] with a host override for each
//! name, so the client under test runs its real code, SSRF guard and TLS
//! validation included, against loopback. Nothing here touches the network.
//!
//! | host               | serves                                                     |
//! |--------------------|------------------------------------------------------------|
//! | `alice-e2e.test`   | `/.well-known/atproto-did`, and `/.well-known/did.json` for did:web |
//! | `plc-e2e.test`     | `/<did:plc>`, the account's DID document                    |
//! | `pds-e2e.test`     | `/.well-known/oauth-protected-resource`, `/xrpc/*`          |
//! | `as-e2e.test`      | the authorization server                                    |
//! | `as-evil.test`, `as-other.test` | other authorization servers, same behaviour, their own issuer |
//!
//! **What the authorization server checks**, every one of which answers the
//! way a real server does (400 with an RFC 6749 error, 401 `invalid_client`):
//!
//! * every DPoP proof: `typ`, ES256 signature under its embedded `jwk`, `htm`,
//!   `htu`, a `jti` never seen before by any host (a replay is
//!   `invalid_dpop_proof`), and the nonce, per [`NoncePolicy`];
//! * client authentication: the `client_id` it was configured with, and for a
//!   confidential client a `private_key_jwt` assertion that verifies under the
//!   client's public JWK, with `iss` = `sub` = `client_id`, `aud` = this
//!   issuer and an `exp` after its `iat`;
//! * `/par`: `response_type=code`, `response_mode=query`,
//!   `code_challenge_method=S256`, a challenge, a state, a redirect and an
//!   `atproto` scope; it stores `{challenge, state, redirect_uri, dpop_jkt,
//!   scope, login_hint}` and returns a `request_uri`;
//! * `/token` `authorization_code`: the code (issued by [`Fake::approve`],
//!   single use), the same issuer as the push, `redirect_uri` byte-equal to
//!   the push's, `code_verifier` whose S256 is the pushed challenge, and a
//!   proof under the pushed key; it answers with `sub` (the account's DID,
//!   or [`Fake::set_sub`]), the granted scope ([`Fake::set_granted_scope`])
//!   and `expires_in` ([`Fake::set_expires_in`]);
//! * `/token` `refresh_token`: single use, rotating; a second use is
//!   `invalid_grant`, as is a refresh token presented under another key or at
//!   another issuer;
//! * `/revoke`: records the token and the proof's key thumbprint, ends the
//!   grant, answers 200.
//!
//! **What the PDS checks** on `/xrpc/*`: `Authorization: DPoP <token>` with a
//! live access token, and a proof as above whose `ath` is that token's hash and
//! whose key is the one the token was issued to; then the nonce, answered as a
//! resource server does (401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"`).
//!
//! **What it does not check**: `iat` freshness (tests pin their own clocks, so
//! there is no shared "now"), a client assertion's `jti` uniqueness (the
//! client resends one assertion on a nonce retry, as the reference does), the
//! client-metadata document (it is handed the client's public JWK instead of
//! fetching it), and `exp` against a clock.
//!
//! The user's part (consent at the authorization endpoint) is
//! [`Fake::approve`]: it takes the authorize URL the client produced and hands
//! back the callback's query parameters.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

use super::{register_tls_host, serve_tls, test_host_override, test_pki, Served, StaticDns};
use crate::flow::CallbackParams;
use crate::keys::SigningKey;
use crate::net::Fetcher;

/// The account's handle, and the host that answers its `/.well-known` files.
pub const HANDLE: &str = "alice-e2e.test";
/// The PDS.
pub const PDS_HOST: &str = "pds-e2e.test";
/// The PDS's authorization server.
pub const AS_HOST: &str = "as-e2e.test";
/// The PLC directory.
pub const PLC_HOST: &str = "plc-e2e.test";
/// An authorization server the account never used: a mix-up target.
pub const EVIL_AS_HOST: &str = "as-evil.test";
/// Another authorization server: where a migrated account's PDS might point.
pub const OTHER_AS_HOST: &str = "as-other.test";

/// The account's DID when it is a did:plc (the default).
pub const PLC_DID: &str = "did:plc:alicee2etestaaaaaaaaaaaa";
/// The account's DID when it is a did:web ([`FakeConfig::did_web`]).
pub const WEB_DID: &str = "did:web:alice-e2e.test";

const AS_HOSTS: [&str; 3] = [AS_HOST, EVIL_AS_HOST, OTHER_AS_HOST];
const ALL_HOSTS: [&str; 6] = [
    HANDLE,
    PDS_HOST,
    AS_HOST,
    PLC_HOST,
    EVIL_AS_HOST,
    OTHER_AS_HOST,
];
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// When a server demands a DPoP nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoncePolicy {
    /// Every proof must carry the server's current nonce; one without it (or
    /// with a stale one, after [`Fake::rotate_nonces`]) is challenged. What
    /// the reference PDS does.
    Always,
    /// Only the server's first proof is challenged; later ones are accepted
    /// with any nonce or none.
    Once,
    /// No nonce is asked for or offered.
    Never,
}

/// How the fake is set up: who the client is, and what kind of account.
#[derive(Clone, Debug)]
pub struct FakeConfig {
    /// The only `client_id` the authorization server accepts.
    pub client_id: String,
    /// The client's public JWK, for a confidential (`private_key_jwt`)
    /// client; `None` for a public client (`token_endpoint_auth_method:
    /// none`), which must then send no assertion.
    pub client_jwk: Option<Value>,
    /// The account is `did:web:alice-e2e.test` instead of [`PLC_DID`].
    pub did_web: bool,
    /// The authorization servers' nonce policy.
    pub as_nonces: NoncePolicy,
    /// The PDS's nonce policy.
    pub pds_nonces: NoncePolicy,
}

impl FakeConfig {
    /// A confidential client: `client_id`, verified by `client_key`'s public
    /// half. A did:plc account, and nonces always required.
    pub fn confidential(client_id: &str, client_key: &SigningKey) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_jwk: Some(client_key.public_jwk().expect("a public JWK")),
            did_web: false,
            as_nonces: NoncePolicy::Always,
            pds_nonces: NoncePolicy::Always,
        }
    }

    /// A public client (the localhost development client).
    pub fn public(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_jwk: None,
            did_web: false,
            as_nonces: NoncePolicy::Always,
            pds_nonces: NoncePolicy::Always,
        }
    }
}

/// One request the fake answered.
#[derive(Clone, Debug)]
pub struct Seen {
    /// The host it was addressed to, without the port.
    pub host: String,
    /// `GET`, `POST`, ...
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// The query, if any.
    pub query: Option<String>,
    /// The headers, names lowercased, in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: String,
    /// The status the fake answered with.
    pub status: u16,
    /// Why the fake refused it, for a 4xx it chose: the error code and its
    /// description (`invalid_grant: PKCE verifier does not match`).
    pub refusal: Option<String>,
}

impl Seen {
    /// The first header called `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The body as a form.
    pub fn form(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(self.body.as_bytes())
            .into_owned()
            .collect()
    }

    /// The first value of form field `name`.
    pub fn form_value(&self, name: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    /// The claims of the request's DPoP proof, unverified.
    pub fn dpop_claims(&self) -> Option<Value> {
        jws_part(self.header("dpop")?, 1)
    }
}

/// A pushed authorization request, as the authorization server stored it.
#[derive(Clone, Debug)]
pub struct Pushed {
    /// The host it was pushed to.
    pub issuer_host: String,
    /// What the push was answered with.
    pub request_uri: String,
    /// The pushing client.
    pub client_id: String,
    /// The client's `state`.
    pub state: String,
    /// The redirect the code may be redeemed with, byte for byte.
    pub redirect_uri: String,
    /// The PKCE S256 challenge.
    pub code_challenge: String,
    /// The thumbprint of the key the push's proof was signed under: the key
    /// the grant is bound to.
    pub dpop_jkt: String,
    /// The requested scope.
    pub scope: String,
    /// The `login_hint`, if one was sent.
    pub login_hint: Option<String>,
}

/// A revocation the authorization server received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    /// The host it was sent to.
    pub issuer_host: String,
    /// The token presented.
    pub token: String,
    /// The thumbprint of the key the request's DPoP proof was signed under,
    /// if it carried one.
    pub dpop_jkt: Option<String>,
}

/// Tokens the authorization server issued (one code exchange or refresh).
#[derive(Clone, Debug)]
pub struct Issued {
    /// The host that issued them.
    pub issuer_host: String,
    /// The `sub` they were issued for.
    pub sub: String,
    /// The access token.
    pub access_token: String,
    /// The refresh token.
    pub refresh_token: String,
    /// The granted scope.
    pub scope: String,
    /// The key they are bound to.
    pub dpop_jkt: String,
    /// Which grant (code exchange) they belong to; refreshes keep it.
    pub grant: usize,
    /// Whether the refresh token has been used.
    pub refresh_used: bool,
}

/// A running fake. Cheap to clone; every clone sees the same state.
#[derive(Clone)]
pub struct Fake {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for Fake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fake")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Fake {
    /// Start the fake on a loopback port.
    pub async fn spawn(config: FakeConfig) -> Self {
        // Before the server is spawned: its leaf must cover every name.
        for host in ALL_HOSTS {
            register_tls_host(host);
        }
        let state = Arc::new(Mutex::new(State::new(config)));
        let shared = Arc::clone(&state);
        let addr = serve_tls(test_pki().leaf(), move |addr| {
            lock(&shared).port = addr.port();
            Arc::new(move |raw: &str| {
                let mut st = lock(&shared);
                st.handle(raw)
            })
        })
        .await;
        Self { addr, state }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// The listener's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `https://<host>:<port>`, the origin `host` is reached at.
    pub fn origin(&self, host: &str) -> String {
        format!("https://{host}:{}", self.addr.port())
    }

    /// The PDS's URL, as the DID document names it.
    pub fn pds_url(&self) -> String {
        self.origin(PDS_HOST)
    }

    /// The authorization server's issuer.
    pub fn issuer(&self) -> String {
        self.origin(AS_HOST)
    }

    /// The PLC directory's URL, for [`crate::login::Client::new`].
    pub fn plc_url(&self) -> String {
        self.origin(PLC_HOST)
    }

    /// The account's DID.
    pub fn did(&self) -> String {
        self.st().did.clone()
    }

    /// A [`Fetcher`] that reaches every fake host (and trusts the test CA).
    pub fn fetcher(&self) -> Fetcher {
        let fetcher = Fetcher::default();
        for host in ALL_HOSTS {
            test_host_override(&fetcher, host, self.addr);
        }
        fetcher
    }

    /// A resolver answering `_atproto.alice-e2e.test` with the account's DID.
    pub fn dns(&self) -> StaticDns {
        let txt = format!("did={}", self.did());
        StaticDns::new().with_txt(&format!("_atproto.{HANDLE}."), &[&[&txt]])
    }

    // ── knobs ────────────────────────────────────────────────────────────

    /// Answer the next code exchanges with this `sub` instead of the
    /// account's DID (`None` restores it).
    pub fn set_sub(&self, sub: Option<&str>) {
        self.st().sub = sub.map(str::to_string);
    }

    /// Grant this scope instead of the requested one (`None` restores it).
    pub fn set_granted_scope(&self, scope: Option<&str>) {
        self.st().granted_scope = scope.map(str::to_string);
    }

    /// The `expires_in` of every token response (default 3600).
    pub fn set_expires_in(&self, secs: i64) {
        self.st().expires_in = secs;
    }

    /// Make the PDS's protected-resource metadata name the authorization
    /// server at `as_host` (one of [`AS_HOST`], [`EVIL_AS_HOST`],
    /// [`OTHER_AS_HOST`]): a repointed or migrated PDS.
    pub fn point_pds_at(&self, as_host: &str) {
        assert!(
            AS_HOSTS.contains(&as_host),
            "{as_host} is not a fake authorization server"
        );
        self.st().pds_points_at = as_host.to_string();
    }

    /// The DID document's `#atproto_pds` endpoint (default [`Fake::pds_url`]).
    pub fn set_pds_endpoint(&self, url: &str) {
        self.st().pds_endpoint = Some(url.to_string());
    }

    /// Serve the DID document as a `302` to another path on the same host
    /// (which would serve it too) instead of directly.
    pub fn redirect_did_documents(&self, on: bool) {
        self.st().redirect_did_documents = on;
    }

    /// What `/.well-known/atproto-did` answers (default: the account's DID;
    /// `None` is a 404).
    pub fn set_well_known_did(&self, did: Option<&str>) {
        self.st().well_known_did = did.map(str::to_string);
    }

    /// Whether the authorization servers advertise a `revocation_endpoint`
    /// (default true).
    pub fn advertise_revocation(&self, on: bool) {
        self.st().advertise_revocation = on;
    }

    /// Change every server's DPoP nonce, as time passing does: the next proof
    /// carrying the old one is challenged (under [`NoncePolicy::Always`]).
    pub fn rotate_nonces(&self) {
        let mut st = self.st();
        st.nonce_generation += 1;
    }

    /// Answer the next request to `/par`, `/token` or `/revoke` (on any
    /// authorization server) with `status` and `{"error":"server_error"}`,
    /// before looking at it.
    pub fn fail_next_with(&self, status: u16) {
        self.st().fail_next = Some(status);
    }

    /// Answer the next authenticated `/xrpc/*` request (one whose token and
    /// proof pass every check) with `status` and `body`: a PDS rejecting a
    /// well-formed call, such as an `applyWrites` it failed on.
    pub fn fail_next_xrpc_with(&self, status: u16, body: Value) {
        self.st().fail_next_xrpc = Some((status, body));
    }

    /// Hold the answer to the next request to `/par`, `/token` or `/revoke`
    /// for `delay` (a slow or hanging server). The request is still handled.
    pub fn stall_next(&self, delay: Duration) {
        self.st().stall_next = Some(delay);
    }

    // ── the user ─────────────────────────────────────────────────────────

    /// Play the user approving at the authorization endpoint: from the
    /// authorize URL the client produced, the callback's query parameters
    /// (`code`, `state`, `iss`). Fails if the URL names no pushed request, or
    /// another client.
    pub fn approve(&self, authorize_url: &str) -> Result<CallbackParams> {
        self.st().approve(authorize_url)
    }

    // ── observation ──────────────────────────────────────────────────────

    /// Every request so far, in order.
    pub fn requests(&self) -> Vec<Seen> {
        self.st().seen.clone()
    }

    /// The requests to `path` on `host`.
    pub fn requests_to(&self, host: &str, path: &str) -> Vec<Seen> {
        self.st()
            .seen
            .iter()
            .filter(|s| s.host == host && s.path == path)
            .cloned()
            .collect()
    }

    /// How many requests went to `path` on `host`.
    pub fn count(&self, host: &str, path: &str) -> usize {
        self.requests_to(host, path).len()
    }

    /// How many requests went to `path` on ANY authorization server: for "the
    /// code was posted nowhere".
    pub fn count_on_any_as(&self, path: &str) -> usize {
        AS_HOSTS.iter().map(|h| self.count(h, path)).sum()
    }

    /// Every pushed authorization request.
    pub fn pushed(&self) -> Vec<Pushed> {
        self.st().pushed.clone()
    }

    /// Every token set issued.
    pub fn issued(&self) -> Vec<Issued> {
        self.st().issued.clone()
    }

    /// Every revocation received.
    pub fn revoked(&self) -> Vec<Revoked> {
        self.st().revoked.clone()
    }

    /// Every refusal the fake made, as `"<path>: <error>: <description>"`.
    /// Nonce challenges are listed too (`use_dpop_nonce`).
    pub fn refusals(&self) -> Vec<String> {
        self.st()
            .seen
            .iter()
            .filter_map(|s| s.refusal.as_ref().map(|r| format!("{}: {r}", s.path)))
            .collect()
    }

    /// The refusals other than nonce challenges.
    pub fn rejections(&self) -> Vec<String> {
        self.refusals()
            .into_iter()
            .filter(|r| !r.contains("use_dpop_nonce"))
            .collect()
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|p| p.into_inner())
}

/// A parsed request.
struct Request {
    host_header: String,
    host: String,
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

impl Request {
    fn parse(raw: &str) -> Self {
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or_default().split_whitespace();
        let method = first.next().unwrap_or_default().to_string();
        let target = first.next().unwrap_or("/");
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (target.to_string(), None),
        };
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let host_header = headers
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let host = host_header
            .rsplit_once(':')
            .map_or(host_header.as_str(), |(h, _)| h)
            .to_string();
        Self {
            host_header,
            host,
            method,
            path,
            query,
            headers,
            body: body.to_string(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn form(&self) -> HashMap<String, String> {
        url::form_urlencoded::parse(self.body.as_bytes())
            .into_owned()
            .collect()
    }

    /// The `htu` a proof for this request must carry.
    fn htu(&self) -> String {
        format!("https://{}{}", self.host_header, self.path)
    }
}

/// Which kind of server is answering: they signal a nonce challenge, and a
/// refusal, differently (RFC 9449 §8 and §9).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    AuthorizationServer,
    ResourceServer,
}

/// A refusal: the status, the RFC 6749 / 6750 error code and a description.
struct Refusal {
    status: u16,
    error: &'static str,
    description: String,
}

fn refuse(status: u16, error: &'static str, description: impl Into<String>) -> Refusal {
    Refusal {
        status,
        error,
        description: description.into(),
    }
}

/// What a handler produced: the reply, and the refusal it records, if any.
struct Reply {
    served: Served,
    refusal: Option<String>,
}

fn json_reply(status: u16, body: &Value) -> Reply {
    typed_reply(status, "application/json", body.to_string())
}

fn typed_reply(status: u16, content_type: &str, body: String) -> Reply {
    Reply {
        served: Served {
            status,
            content_type: content_type.to_string(),
            headers: Vec::new(),
            body: body.into_bytes(),
            delay: None,
        },
        refusal: None,
    }
}

impl Reply {
    fn header(mut self, k: &str, v: &str) -> Self {
        self.served.headers.push((k.to_string(), v.to_string()));
        self
    }
}

/// Everything the fake remembers.
struct State {
    port: u16,
    config: FakeConfig,
    did: String,
    // knobs
    sub: Option<String>,
    granted_scope: Option<String>,
    expires_in: i64,
    pds_points_at: String,
    pds_endpoint: Option<String>,
    redirect_did_documents: bool,
    well_known_did: Option<String>,
    advertise_revocation: bool,
    nonce_generation: u32,
    fail_next: Option<u16>,
    fail_next_xrpc: Option<(u16, Value)>,
    stall_next: Option<Duration>,
    // memory
    seen: Vec<Seen>,
    jtis: HashSet<String>,
    /// Per role, whether its first proof has been challenged (`Once`).
    challenged: HashSet<&'static str>,
    pushed: Vec<Pushed>,
    /// Code → (index into `pushed`, used).
    codes: HashMap<String, (usize, bool)>,
    issued: Vec<Issued>,
    revoked: Vec<Revoked>,
    /// Grants ended by a revocation.
    revoked_grants: HashSet<usize>,
    counter: usize,
}

impl State {
    fn new(config: FakeConfig) -> Self {
        let did = if config.did_web { WEB_DID } else { PLC_DID }.to_string();
        Self {
            port: 0,
            well_known_did: Some(did.clone()),
            did,
            config,
            sub: None,
            granted_scope: None,
            expires_in: 3600,
            pds_points_at: AS_HOST.to_string(),
            pds_endpoint: None,
            redirect_did_documents: false,
            advertise_revocation: true,
            nonce_generation: 0,
            fail_next: None,
            fail_next_xrpc: None,
            stall_next: None,
            seen: Vec::new(),
            jtis: HashSet::new(),
            challenged: HashSet::new(),
            pushed: Vec::new(),
            codes: HashMap::new(),
            issued: Vec::new(),
            revoked: Vec::new(),
            revoked_grants: HashSet::new(),
            counter: 0,
        }
    }

    fn next(&mut self) -> usize {
        self.counter += 1;
        self.counter
    }

    fn origin(&self, host: &str) -> String {
        format!("https://{host}:{}", self.port)
    }

    fn handle(&mut self, raw: &str) -> Served {
        let req = Request::parse(raw);
        let reply = self.route(&req);
        self.seen.push(Seen {
            host: req.host.clone(),
            method: req.method.clone(),
            path: req.path.clone(),
            query: req.query.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            status: reply.served.status,
            refusal: reply.refusal,
        });
        reply.served
    }

    fn route(&mut self, req: &Request) -> Reply {
        let host = req.host.as_str();
        match host {
            HANDLE => self.handle_host(req),
            PLC_HOST => self.plc(req),
            PDS_HOST => self.pds(req),
            h if AS_HOSTS.contains(&h) => self.authorization_server(req),
            _ => json_reply(421, &json!({"error": "misdirected", "host": host})),
        }
    }

    // ── identity ─────────────────────────────────────────────────────────

    fn did_document(&self) -> Value {
        let pds = self
            .pds_endpoint
            .clone()
            .unwrap_or_else(|| self.origin(PDS_HOST));
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": self.did,
            "alsoKnownAs": [format!("at://{HANDLE}")],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": pds,
            }],
        })
    }

    /// A DID document, or a redirect to a copy of it (which a client must
    /// not follow: the copy's host is not the one the DID names).
    fn serve_did_document(&self, req: &Request, canonical: &str) -> Reply {
        if req.path == canonical && self.redirect_did_documents {
            let to = format!("{}/moved{canonical}", self.origin(&req.host));
            return typed_reply(302, "text/plain", String::new()).header("Location", &to);
        }
        typed_reply(
            200,
            "application/did+ld+json",
            self.did_document().to_string(),
        )
    }

    fn handle_host(&self, req: &Request) -> Reply {
        match req.path.as_str() {
            "/.well-known/atproto-did" => match &self.well_known_did {
                Some(did) => typed_reply(200, "text/plain", did.clone()),
                None => typed_reply(404, "text/plain", "no such handle".into()),
            },
            "/.well-known/did.json" | "/moved/.well-known/did.json" if self.config.did_web => {
                self.serve_did_document(req, "/.well-known/did.json")
            }
            _ => json_reply(404, &json!({"error": "not found"})),
        }
    }

    fn plc(&self, req: &Request) -> Reply {
        let canonical = format!("/{}", self.did);
        if !self.config.did_web
            && (req.path == canonical || req.path == format!("/moved{canonical}"))
        {
            return self.serve_did_document(req, &canonical);
        }
        json_reply(404, &json!({"message": "DID not registered"}))
    }

    // ── the PDS ──────────────────────────────────────────────────────────

    fn pds(&mut self, req: &Request) -> Reply {
        if req.path == "/.well-known/oauth-protected-resource" {
            return json_reply(
                200,
                &json!({
                    "resource": self.origin(PDS_HOST),
                    "authorization_servers": [self.origin(&self.pds_points_at)],
                }),
            );
        }
        if req.path.starts_with("/xrpc/") {
            return self.xrpc(req);
        }
        json_reply(404, &json!({"error": "not found"}))
    }

    /// `/xrpc/*` as a DPoP resource server (RFC 9449 §7): a live access
    /// token in `Authorization: DPoP`, and a proof that binds it (`ath`) under
    /// the key it was issued to. Answers `{"did": <sub>}`.
    fn xrpc(&mut self, req: &Request) -> Reply {
        let reply = match self.xrpc_checked(req) {
            Ok(body) => match self.fail_next_xrpc.take() {
                Some((status, failure)) => {
                    let mut reply = json_reply(status, &failure);
                    reply.refusal = Some("injected by fail_next_xrpc_with".into());
                    reply
                }
                None => json_reply(200, &body),
            },
            Err(refusal) => refusal_reply(Role::ResourceServer, refusal),
        };
        self.offer_nonce(Role::ResourceServer, reply)
    }

    fn xrpc_checked(&mut self, req: &Request) -> Result<Value, Refusal> {
        let auth = req.header("authorization").unwrap_or_default();
        let Some(token) = auth.strip_prefix("DPoP ") else {
            return Err(refuse(
                401,
                "invalid_token",
                "no `Authorization: DPoP` access token",
            ));
        };
        let Some(issued) = self
            .issued
            .iter()
            .find(|t| t.access_token == token)
            .cloned()
        else {
            return Err(refuse(401, "invalid_token", "unknown access token"));
        };
        if self.revoked_grants.contains(&issued.grant) {
            return Err(refuse(401, "invalid_token", "the grant was revoked"));
        }
        let jkt = self.check_proof(req, Role::ResourceServer, Some(token))?;
        if jkt != issued.dpop_jkt {
            return Err(refuse(
                401,
                "invalid_dpop_proof",
                "the proof's DPoP key is not the one the token was issued to",
            ));
        }
        Ok(json!({
            "nsid": req.path.trim_start_matches("/xrpc/"),
            "did": issued.sub,
        }))
    }

    // ── the authorization server ─────────────────────────────────────────

    fn as_metadata(&self, host: &str) -> Value {
        let issuer = self.origin(host);
        let mut doc = json!({
            "issuer": issuer,
            "pushed_authorization_request_endpoint": format!("{issuer}/par"),
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "protected_resources": [self.origin(PDS_HOST)],
            "client_id_metadata_document_supported": true,
            "require_pushed_authorization_requests": true,
            "authorization_response_iss_parameter_supported": true,
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["atproto", "transition:generic"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "fragment"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
        });
        if self.advertise_revocation {
            doc["revocation_endpoint"] = json!(format!("{issuer}/revoke"));
        }
        doc
    }

    fn authorization_server(&mut self, req: &Request) -> Reply {
        if req.method == "GET" && req.path == "/.well-known/oauth-authorization-server" {
            return json_reply(200, &self.as_metadata(&req.host));
        }
        if req.method != "POST" || !["/par", "/token", "/revoke"].contains(&req.path.as_str()) {
            return json_reply(404, &json!({"error": "not found"}));
        }
        if let Some(status) = self.fail_next.take() {
            let mut reply = json_reply(status, &json!({"error": "server_error"}));
            reply.refusal = Some("server_error: injected by fail_next_with".into());
            return reply;
        }
        let delay = self.stall_next.take();
        let result = match req.path.as_str() {
            "/par" => self.par(req),
            "/token" => self.token(req),
            _ => self.revoke(req),
        };
        let reply =
            result.unwrap_or_else(|refusal| refusal_reply(Role::AuthorizationServer, refusal));
        let mut reply = self.offer_nonce(Role::AuthorizationServer, reply);
        reply.served.delay = delay;
        reply
    }

    /// `/par`: a proof, client authentication, and a well-formed request;
    /// stored, and answered with a `request_uri`.
    fn par(&mut self, req: &Request) -> Result<Reply, Refusal> {
        let issuer = self.origin(&req.host);
        let jkt = self.check_proof(req, Role::AuthorizationServer, None)?;
        let form = req.form();
        self.check_client(&form, &issuer)?;
        let field = |k: &str| form.get(k).cloned().unwrap_or_default();
        for (name, wanted) in [
            ("response_type", "code"),
            ("response_mode", "query"),
            ("code_challenge_method", "S256"),
        ] {
            if field(name) != wanted {
                return Err(refuse(
                    400,
                    "invalid_request",
                    format!("{name} must be {wanted:?}, got {:?}", field(name)),
                ));
            }
        }
        for name in ["code_challenge", "state", "redirect_uri"] {
            if field(name).is_empty() {
                return Err(refuse(400, "invalid_request", format!("no {name}")));
            }
        }
        if !field("scope").split(' ').any(|s| s == "atproto") {
            return Err(refuse(
                400,
                "invalid_scope",
                "the scope must include atproto",
            ));
        }
        let request_uri = format!("urn:ietf:params:oauth:request_uri:req-{}", self.next());
        self.pushed.push(Pushed {
            issuer_host: req.host.clone(),
            request_uri: request_uri.clone(),
            client_id: field("client_id"),
            state: field("state"),
            redirect_uri: field("redirect_uri"),
            code_challenge: field("code_challenge"),
            dpop_jkt: jkt,
            scope: field("scope"),
            login_hint: form.get("login_hint").cloned(),
        });
        Ok(json_reply(
            201,
            &json!({"request_uri": request_uri, "expires_in": 60}),
        ))
    }

    /// `/token`: a proof and client authentication, then the grant.
    fn token(&mut self, req: &Request) -> Result<Reply, Refusal> {
        let issuer = self.origin(&req.host);
        let jkt = self.check_proof(req, Role::AuthorizationServer, None)?;
        let form = req.form();
        self.check_client(&form, &issuer)?;
        match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => self.exchange_code(&req.host, &form, &jkt),
            Some("refresh_token") => self.refresh(&req.host, &form, &jkt),
            other => Err(refuse(
                400,
                "unsupported_grant_type",
                format!("grant_type {other:?}"),
            )),
        }
    }

    fn exchange_code(
        &mut self,
        host: &str,
        form: &HashMap<String, String>,
        jkt: &str,
    ) -> Result<Reply, Refusal> {
        let field = |k: &str| form.get(k).cloned().unwrap_or_default();
        let code = field("code");
        let Some(&(idx, used)) = self.codes.get(&code) else {
            return Err(refuse(400, "invalid_grant", "unknown code"));
        };
        if used {
            return Err(refuse(400, "invalid_grant", "the code was already used"));
        }
        let pushed = self.pushed[idx].clone();
        if pushed.issuer_host != host {
            return Err(refuse(
                400,
                "invalid_grant",
                "the code was issued by another server",
            ));
        }
        if field("redirect_uri") != pushed.redirect_uri {
            return Err(refuse(
                400,
                "invalid_grant",
                "redirect_uri is not byte-equal to the pushed one",
            ));
        }
        if s256(&field("code_verifier")) != pushed.code_challenge {
            return Err(refuse(
                400,
                "invalid_grant",
                "the code_verifier does not match the pushed code_challenge (PKCE S256)",
            ));
        }
        if jkt != pushed.dpop_jkt {
            return Err(refuse(
                400,
                "invalid_grant",
                "the proof's DPoP key is not the one the request was pushed under",
            ));
        }
        // Spent only by a successful exchange, so a negative control can be
        // followed by the correct request.
        self.codes.insert(code, (idx, true));
        let sub = self.sub.clone().unwrap_or_else(|| self.did.clone());
        let scope = self.granted_scope.clone().unwrap_or(pushed.scope);
        let grant = self.next();
        Ok(self.issue(host, sub, scope, jkt, grant))
    }

    /// The refresh grant: single use, rotating. A second use is
    /// `invalid_grant` and, as atproto servers do on refresh-token reuse,
    /// ends the whole grant.
    fn refresh(
        &mut self,
        host: &str,
        form: &HashMap<String, String>,
        jkt: &str,
    ) -> Result<Reply, Refusal> {
        let presented = form.get("refresh_token").cloned().unwrap_or_default();
        let Some(i) = self
            .issued
            .iter()
            .position(|t| t.refresh_token == presented)
        else {
            return Err(refuse(400, "invalid_grant", "unknown refresh token"));
        };
        let old = self.issued[i].clone();
        if self.revoked_grants.contains(&old.grant) {
            return Err(refuse(400, "invalid_grant", "the grant was revoked"));
        }
        if old.refresh_used {
            self.revoked_grants.insert(old.grant);
            return Err(refuse(
                400,
                "invalid_grant",
                "the refresh token was already used",
            ));
        }
        if old.issuer_host != host {
            return Err(refuse(
                400,
                "invalid_grant",
                "the refresh token was issued by another server",
            ));
        }
        if old.dpop_jkt != jkt {
            return Err(refuse(
                400,
                "invalid_grant",
                "the proof's DPoP key is not the one the grant is bound to",
            ));
        }
        self.issued[i].refresh_used = true;
        Ok(self.issue(host, old.sub, old.scope, jkt, old.grant))
    }

    fn issue(&mut self, host: &str, sub: String, scope: String, jkt: &str, grant: usize) -> Reply {
        let n = self.next();
        let issued = Issued {
            issuer_host: host.to_string(),
            sub,
            access_token: format!("at-{n}"),
            refresh_token: format!("rt-{n}"),
            scope,
            dpop_jkt: jkt.to_string(),
            grant,
            refresh_used: false,
        };
        let body = json!({
            "access_token": issued.access_token,
            "token_type": "DPoP",
            "refresh_token": issued.refresh_token,
            "scope": issued.scope,
            "sub": issued.sub,
            "expires_in": self.expires_in,
        });
        self.issued.push(issued);
        json_reply(200, &body)
    }

    /// `/revoke` (RFC 7009): recorded, the grant ended, 200 whatever the
    /// token was.
    fn revoke(&mut self, req: &Request) -> Result<Reply, Refusal> {
        let issuer = self.origin(&req.host);
        let jkt = match req.header("dpop") {
            Some(_) => Some(self.check_proof(req, Role::AuthorizationServer, None)?),
            None => None,
        };
        let form = req.form();
        self.check_client(&form, &issuer)?;
        let token = form.get("token").cloned().unwrap_or_default();
        if let Some(t) = self
            .issued
            .iter()
            .find(|t| t.refresh_token == token || t.access_token == token)
        {
            self.revoked_grants.insert(t.grant);
        }
        self.revoked.push(Revoked {
            issuer_host: req.host.clone(),
            token,
            dpop_jkt: jkt,
        });
        Ok(json_reply(200, &json!({})))
    }

    // ── the checks every endpoint shares ─────────────────────────────────

    /// The server's current nonce.
    fn nonce(&self, role: Role) -> String {
        let prefix = match role {
            Role::AuthorizationServer => "as",
            Role::ResourceServer => "pds",
        };
        format!("{prefix}-nonce-{}", self.nonce_generation)
    }

    fn policy(&self, role: Role) -> NoncePolicy {
        match role {
            Role::AuthorizationServer => self.config.as_nonces,
            Role::ResourceServer => self.config.pds_nonces,
        }
    }

    /// Every answer from a server that uses nonces offers its current one.
    fn offer_nonce(&self, role: Role, reply: Reply) -> Reply {
        if self.policy(role) == NoncePolicy::Never {
            return reply;
        }
        let nonce = self.nonce(role);
        reply.header("DPoP-Nonce", &nonce)
    }

    /// Verify the request's DPoP proof and return its key's thumbprint.
    ///
    /// In order: present; `typ` and `alg`; a public `jwk` whose key verifies
    /// the signature; `htm` and `htu` are this request's; a `jti` never seen
    /// on any host (recorded here, so even a proof that is then challenged
    /// for a nonce cannot be sent again); `ath` when `access_token` is given;
    /// then the nonce.
    fn check_proof(
        &mut self,
        req: &Request,
        role: Role,
        access_token: Option<&str>,
    ) -> Result<String, Refusal> {
        let status = match role {
            Role::AuthorizationServer => 400,
            Role::ResourceServer => 401,
        };
        let bad = |d: String| refuse(status, "invalid_dpop_proof", d);
        let proof = req
            .header("dpop")
            .ok_or_else(|| bad("no DPoP proof".into()))?;
        let header = jws_part(proof, 0).ok_or_else(|| bad("the header is not JSON".into()))?;
        if header["typ"] != "dpop+jwt" {
            return Err(bad(format!("typ is {}, not dpop+jwt", header["typ"])));
        }
        if header["alg"] != "ES256" {
            return Err(bad(format!("alg is {}, not ES256", header["alg"])));
        }
        let jwk = header
            .get("jwk")
            .ok_or_else(|| bad("no jwk in the header".into()))?;
        if jwk.get("d").is_some() {
            return Err(bad("the jwk carries a private key".into()));
        }
        verify_es256(jwk, proof).map_err(|e| {
            bad(format!(
                "the signature does not verify under the embedded jwk: {e:#}"
            ))
        })?;
        let claims = jws_part(proof, 1).ok_or_else(|| bad("the claims are not JSON".into()))?;
        if claims["htm"] != req.method.as_str() {
            return Err(bad(format!("htm is {}, not {}", claims["htm"], req.method)));
        }
        if claims["htu"] != req.htu().as_str() {
            return Err(bad(format!("htu is {}, not {}", claims["htu"], req.htu())));
        }
        let jti = claims["jti"]
            .as_str()
            .filter(|j| !j.is_empty())
            .ok_or_else(|| bad("no jti".into()))?;
        if !self.jtis.insert(jti.to_string()) {
            return Err(bad(format!("jti {jti} was already used: a replayed proof")));
        }
        if let Some(token) = access_token {
            match claims["ath"].as_str() {
                None => {
                    return Err(bad(
                        "no ath: the proof does not bind the access token".into()
                    ))
                }
                Some(ath) if ath != s256(token) => {
                    return Err(bad("ath is not the access token's hash".into()))
                }
                Some(_) => {}
            }
        }
        let jkt = SigningKey::public_thumbprint_of(&jwk.to_string())
            .map_err(|e| bad(format!("the jwk has no thumbprint: {e:#}")))?;

        let current = self.nonce(role);
        let carried = claims["nonce"].as_str();
        let accepted = match self.policy(role) {
            NoncePolicy::Never => true,
            NoncePolicy::Always => carried == Some(current.as_str()),
            NoncePolicy::Once => {
                let first = self.challenged.insert(match role {
                    Role::AuthorizationServer => "as",
                    Role::ResourceServer => "pds",
                });
                !first || carried == Some(current.as_str())
            }
        };
        if !accepted {
            return Err(refuse(
                status,
                "use_dpop_nonce",
                format!("a DPoP nonce is required (carried {carried:?})"),
            ));
        }
        Ok(jkt)
    }

    /// Client authentication: the configured `client_id`, and for a
    /// confidential client a `private_key_jwt` assertion under its key, for
    /// this issuer.
    fn check_client(&self, form: &HashMap<String, String>, issuer: &str) -> Result<(), Refusal> {
        let bad = |d: String| refuse(401, "invalid_client", d);
        let client_id = form
            .get("client_id")
            .map(String::as_str)
            .unwrap_or_default();
        if client_id != self.config.client_id {
            return Err(bad(format!("unknown client_id {client_id:?}")));
        }
        let assertion = form.get("client_assertion");
        let Some(jwk) = &self.config.client_jwk else {
            if assertion.is_some() {
                return Err(bad("a public client sent a client assertion".into()));
            }
            return Ok(());
        };
        if form.get("client_assertion_type").map(String::as_str) != Some(JWT_BEARER) {
            return Err(bad("client_assertion_type is not jwt-bearer".into()));
        }
        let assertion = assertion.ok_or_else(|| bad("no client_assertion".into()))?;
        let header = jws_part(assertion, 0).ok_or_else(|| bad("assertion header".into()))?;
        if header["alg"] != "ES256" {
            return Err(bad(format!("assertion alg is {}", header["alg"])));
        }
        verify_es256(jwk, assertion).map_err(|e| {
            bad(format!(
                "the client assertion does not verify under the client's key: {e:#}"
            ))
        })?;
        let claims = jws_part(assertion, 1).ok_or_else(|| bad("assertion claims".into()))?;
        for name in ["iss", "sub"] {
            if claims[name] != client_id {
                return Err(bad(format!(
                    "assertion {name} is {}, not the client_id",
                    claims[name]
                )));
            }
        }
        if claims["aud"] != issuer {
            return Err(bad(format!(
                "assertion aud is {}, not this issuer {issuer:?}",
                claims["aud"]
            )));
        }
        match (claims["iat"].as_i64(), claims["exp"].as_i64()) {
            (Some(iat), Some(exp)) if exp > iat => Ok(()),
            _ => Err(bad("assertion exp is missing or not after its iat".into())),
        }
    }

    fn approve(&mut self, authorize_url: &str) -> Result<CallbackParams> {
        let url = url::Url::parse(authorize_url).context("the authorize URL")?;
        let host = url.host_str().unwrap_or_default().to_string();
        if !AS_HOSTS.contains(&host.as_str()) || url.path() != "/authorize" {
            bail!("{authorize_url} is not a fake authorization endpoint");
        }
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let request_uri = query.get("request_uri").context("no request_uri")?;
        let idx = self
            .pushed
            .iter()
            .position(|p| p.request_uri == *request_uri && p.issuer_host == host)
            .context("no pushed request has that request_uri")?;
        let pushed = self.pushed[idx].clone();
        if query.get("client_id") != Some(&pushed.client_id) {
            bail!("the authorize URL names another client than the push");
        }
        let code = format!("code-{}", self.next());
        self.codes.insert(code.clone(), (idx, false));
        Ok(CallbackParams {
            code: Some(code),
            state: Some(pushed.state),
            iss: Some(self.origin(&host)),
            ..Default::default()
        })
    }
}

/// A refusal as the server answers it: an AS with an RFC 6749 error body, a
/// resource server with `WWW-Authenticate: DPoP error=...` too.
fn refusal_reply(role: Role, refusal: Refusal) -> Reply {
    let mut reply = match role {
        Role::AuthorizationServer => json_reply(
            refusal.status,
            &json!({"error": refusal.error, "error_description": refusal.description}),
        ),
        Role::ResourceServer => json_reply(
            refusal.status,
            &json!({"error": refusal.error, "message": refusal.description}),
        )
        .header(
            "WWW-Authenticate",
            &format!(
                "DPoP error=\"{}\", error_description=\"{}\"",
                refusal.error,
                refusal.description.replace(['"', '\\'], "'")
            ),
        ),
    };
    reply.refusal = Some(format!("{}: {}", refusal.error, refusal.description));
    reply
}

/// `base64url(sha256(input))`: a PKCE S256 challenge, or an `ath`.
fn s256(input: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Verify a compact ES256 JWS under a public P-256 JWK.
fn verify_es256(jwk: &Value, jws: &str) -> Result<()> {
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};

    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        bail!("not a P-256 key");
    }
    let coord = |name: &str| -> Result<Vec<u8>> {
        let raw = jwk[name].as_str().with_context(|| format!("no {name}"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .with_context(|| format!("{name} is not base64url"))?;
        if bytes.len() != 32 {
            bail!("{name} is {} bytes", bytes.len());
        }
        Ok(bytes)
    };
    let mut sec1 = vec![0x04];
    sec1.extend(coord("x")?);
    sec1.extend(coord("y")?);
    let key = VerifyingKey::from_sec1_bytes(&sec1).context("not a point on P-256")?;
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        bail!("{} segments", parts.len());
    }
    let raw = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("signature base64url")?;
    let signature = Signature::from_slice(&raw).context("not a P-256 signature")?;
    let input = format!("{}.{}", parts[0], parts[1]);
    key.verify(input.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("bad signature"))
}

/// Decode one segment of a compact JWS as JSON.
fn jws_part(jws: &str, idx: usize) -> Option<Value> {
    let part = jws.split('.').nth(idx)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}
