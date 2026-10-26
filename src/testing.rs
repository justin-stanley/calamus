//! Test helpers for code that uses calamus: host overrides for a
//! [`Fetcher`], a test certificate authority, a loopback TLS server, and plain
//! HTTP test servers.
//!
//! **Compiled only for calamus's own tests and the `test-util` feature.** The host
//! override deliberately bypasses the SSRF guard for a named host, so it must
//! never reach a release build: enable `test-util` from `[dev-dependencies]`
//! only. `scripts/ci.sh` proves this module is absent from a build without the
//! feature.
//!
//! Ported from FeatherReader `src/net.rs`, where these were `#[cfg(test)]` items
//! (`test_host_override`, `test_pki`, `spawn_tls`, `TestResponse`,
//! `TEST_TLS_HOSTS`) and test-module helpers (`serve_body`,
//! `serve_bodies_in_sequence`, ...). Two changes:
//!
//! * the host-override table is per [`Fetcher`] rather than process-wide, so
//!   [`test_host_override`] names the Fetcher it applies to and a Fetcher no test
//!   touched has none;
//! * the TLS test hostnames are a registration API, [`register_tls_host`], seeded
//!   with [`DEFAULT_TLS_HOSTS`], instead of a fixed list a caller had to edit. The
//!   CA is one per process; each [`spawn_tls`] server gets a fresh leaf covering
//!   every hostname registered so far, so register a name before spawning the
//!   server that must answer for it.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use anyhow::{Context, Result};

use crate::net::Fetcher;

pub mod fake;

/// An [`AuthorizationServer`](crate::discovery::AuthorizationServer) with any
/// issuer and endpoints, **unchecked**: none of discovery's validations (issuer
/// equals the fetched-from URL, endpoints on the issuer's origin) are applied.
///
/// Test-only on purpose. Outside `test-util` the type is constructible only by
/// discovery, because a context trusts the pairing of its issuer with its
/// endpoints; production code caches a discovered value rather than rebuilding
/// one.
pub fn authorization_server(
    issuer: &str,
    par_endpoint: &str,
    authorization_endpoint: &str,
    token_endpoint: &str,
    revocation_endpoint: Option<&str>,
) -> crate::discovery::AuthorizationServer {
    crate::discovery::AuthorizationServer::unchecked(
        issuer.to_string(),
        par_endpoint.to_string(),
        authorization_endpoint.to_string(),
        token_endpoint.to_string(),
        revocation_endpoint.map(str::to_string),
    )
}

/// `server` with its revocation endpoint replaced by `endpoint`, **unchecked**
/// (it may be on any origin, or absent). Test-only, as
/// [`authorization_server`] is.
pub fn with_revocation_endpoint(
    server: crate::discovery::AuthorizationServer,
    endpoint: Option<&str>,
) -> crate::discovery::AuthorizationServer {
    server.set_revocation_endpoint(endpoint.map(str::to_string))
}

/// Point `host` at `addr` for `fetcher`, bypassing DNS **and** the forbidden-IP
/// check for that host only, and make `fetcher` trust the test CA
/// ([`test_pki`]).
///
/// Bypassing the IP check is the entire point: the test server is on loopback,
/// which the guard is right to refuse. Only the registered host is exempt —
/// anything else in the same test, including every redirect target, still goes
/// through the real check. That is what makes a redirect test meaningful.
///
/// A host may also be registered as `"host:port"`; the bare host wins. reqwest's
/// connect pin ignores the port, so the test URL's own port is what reaches the
/// server.
pub fn test_host_override(fetcher: &Fetcher, host: &str, addr: SocketAddr) {
    fetcher.overrides.insert(host, addr);
    fetcher.clients.test_ca.trust();
}

/// A [`Fetcher`]'s host → address overrides.
///
/// **Defined here, and only here, on purpose.** This module does not exist
/// without `test-util`, so neither does this type: a Fetcher field of this type,
/// or a call to [`HostOverrides::lookup`], cannot be compiled into a build
/// without the feature, whatever happens to the `cfg` attributes in `net`. The
/// seam is absent by construction, not by remembering to gate it.
#[derive(Debug, Default)]
pub(crate) struct HostOverrides(Mutex<HashMap<String, SocketAddr>>);

impl HostOverrides {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, SocketAddr>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn insert(&self, host: &str, addr: SocketAddr) {
        self.map().insert(host.to_string(), addr);
    }

    /// The override for `name`, or for `name:port`; the bare host wins.
    pub(crate) fn lookup(&self, name: &str, port: u16) -> Option<SocketAddr> {
        let map = self.map();
        map.get(name)
            .copied()
            .or_else(|| map.get(&format!("{name}:{port}")).copied())
    }

    pub(crate) fn len(&self) -> usize {
        self.map().len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.map().is_empty()
    }
}

/// Whether a Fetcher's pinned clients trust the test CA. Set by
/// [`test_host_override`] and never otherwise; defined only here for the same
/// reason as [`HostOverrides`].
#[derive(Debug, Default)]
pub(crate) struct TestCaTrust(AtomicBool);

impl TestCaTrust {
    fn trust(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_trusted(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The hostnames every test leaf carries before any [`register_tls_host`] call:
/// the ones calamus's own tests serve over TLS. A wildcard would not cover the
/// multi-label names, so they are listed, and the list is deliberately narrow:
/// the certificate is supposed to be.
pub const DEFAULT_TLS_HOSTS: &[&str] = &[
    "pds-e2e.test",
    "as-e2e.test",
    "feed-tls.test",
    "as-evil.test",
    // A second authorization server, for a session that moves issuer mid
    // sign-out (its token must never reach the first one).
    "as-other.test",
];

static TLS_HOSTS: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(DEFAULT_TLS_HOSTS.iter().map(|h| (*h).to_string()).collect()));

/// Add `host` to the names the test leaf is valid for, for every [`spawn_tls`]
/// server spawned after this call. Idempotent.
///
/// Register before spawning: a server already running keeps the leaf it was
/// given. Panics if `host` cannot be a DNS SAN.
pub fn register_tls_host(host: &str) {
    let covered = CA_PERMITTED_DNS
        .iter()
        .any(|zone| host == *zone || host.ends_with(&format!(".{zone}")));
    if !covered {
        panic!("{host:?} is outside the test CA's name constraints ({CA_PERMITTED_DNS:?})");
    }
    let san: Result<rcgen::SanType, _> = host.try_into().map(rcgen::SanType::DnsName);
    if let Err(e) = san {
        panic!("{host:?} cannot be a certificate SAN: {e}");
    }
    TLS_HOSTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(host.to_string());
}

/// The DNS subtrees the test CA may vouch for, as X.509 name constraints:
/// `.test` (RFC 2606, never a real host) and `localhost`, which a caller's tests
/// use for a self-hosted server. A leaf the CA signs for any other name fails
/// validation, so the test CA cannot be turned against a real host.
pub const CA_PERMITTED_DNS: &[&str] = &["test", "localhost"];

/// The TEST certificate authority, generated once per process.
///
/// **Why this exists at all.** An OAuth issuer is required to be `https`, so a
/// plain-HTTP loopback server cannot stand in for an authorization server —
/// which meant the real login could never be driven end to end, and the wiring
/// between its tested core and the network had no coverage. A review proved that
/// gap was live: the authorization-server mix-up defence could be disabled in that
/// wiring with the whole suite green.
///
/// **Why a CA rather than relaxing the rule.** The alternative was a test-only
/// escape from the https requirement. That would *suspend* a security rule; this
/// *satisfies* it — the server really presents a certificate and the client
/// really validates the chain. It also keeps the tests that assert `http` issuers
/// are REJECTED meaningful, which a blanket relaxation would not.
pub struct TestPki {
    /// PEM of the CA certificate, for a client's root store.
    pub ca_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

/// A leaf certificate issued by the test CA, for a test server.
pub struct TestLeaf {
    /// PEM of the leaf certificate, for the server.
    pub leaf_pem: String,
    /// PEM of the leaf private key, for the server.
    pub leaf_key_pem: String,
}

impl TestPki {
    /// A fresh leaf valid for every hostname registered so far
    /// ([`DEFAULT_TLS_HOSTS`] plus each [`register_tls_host`]).
    pub fn leaf(&self) -> TestLeaf {
        let hosts: Vec<String> = TLS_HOSTS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect();
        self.leaf_for(hosts)
    }

    /// A leaf for exactly `hosts`, registered or not: for the test that the CA
    /// cannot vouch for a name outside its constraints.
    pub(crate) fn leaf_for(&self, hosts: Vec<String>) -> TestLeaf {
        use rcgen::{CertificateParams, DnType, KeyPair, SanType};

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "calamus test leaf");
        leaf_params.subject_alt_names = hosts
            .into_iter()
            .map(|h| SanType::DnsName(h.try_into().expect("test SAN")))
            .collect();
        let leaf_key = KeyPair::generate().expect("test leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &self.issuer)
            .expect("test leaf cert");
        TestLeaf {
            leaf_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }
}

/// The process's test CA (see [`TestPki`]).
pub fn test_pki() -> &'static TestPki {
    static PKI: OnceLock<TestPki> = OnceLock::new();
    PKI.get_or_init(|| {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "calamus test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: CA_PERMITTED_DNS
                .iter()
                .map(|zone| rcgen::GeneralSubtree::DnsName((*zone).to_string()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().expect("test CA key");
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key)
            .expect("test CA cert");
        TestPki {
            ca_pem: ca_cert.pem(),
            issuer: rcgen::Issuer::new(ca_params, ca_key),
        }
    })
}

/// The test CA as a reqwest root, for a Fetcher a test gave a host override.
pub(crate) fn test_ca_certificate() -> Result<reqwest::Certificate> {
    reqwest::Certificate::from_pem(test_pki().ca_pem.as_bytes()).context("parsing the test CA")
}

/// A loopback HTTPS server presenting a test leaf, routing by path.
///
/// The point of the TLS is not TLS: it is that an OAuth issuer must be `https`,
/// so nothing could drive a real login against a local server. The client
/// validates this chain for real — no invalid-cert acceptance anywhere.
///
/// `build_routes` gets the bound address (documents have to name their own port)
/// and maps a path to its canned replies: the Nth hit on a path gets the Nth
/// reply, and the last one repeats. Unknown paths 404. Every request (head, and
/// the body when `content-length` gives its length) is recorded in the returned
/// log.
pub async fn spawn_tls<F>(build_routes: F) -> (SocketAddr, Arc<Mutex<Vec<String>>>)
where
    F: FnOnce(SocketAddr) -> HashMap<String, Vec<TestResponse>>,
{
    spawn_tls_with_leaf(test_pki().leaf(), build_routes).await
}

/// [`spawn_tls`] presenting a given leaf.
pub(crate) async fn spawn_tls_with_leaf<F>(
    leaf: TestLeaf,
    build_routes: F,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>)
where
    F: FnOnce(SocketAddr) -> HashMap<String, Vec<TestResponse>>,
{
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let addr = serve_tls(leaf, move |addr| {
        // Routes are built from the bound address: the documents have to name
        // their own port, and the port is not known until the listener exists.
        let routes = build_routes(addr);
        let hits: Mutex<HashMap<String, usize>> = Default::default();
        Arc::new(move |req: &str| {
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            sink.lock().unwrap().push(req.to_string());
            // Nth hit on this path picks the Nth canned reply; the last one
            // repeats. That is what lets a route answer a nonce challenge
            // once and something else afterwards — the only way to observe
            // whether a request was RETRIED.
            let n = {
                let mut c = hits.lock().unwrap();
                let e = c.entry(path.clone()).or_insert(0usize);
                let n = *e;
                *e += 1;
                n
            };
            let reply = routes
                .get(&path)
                .and_then(|v| v.get(n.min(v.len().saturating_sub(1))))
                .cloned()
                .unwrap_or_else(|| TestResponse::json(404, "not found"));
            Served {
                status: reply.status,
                content_type: "application/json".into(),
                headers: reply.headers,
                body: reply.body.into_bytes(),
                delay: None,
            }
        })
    })
    .await;
    (addr, log)
}

/// One reply from [`serve_tls`]'s handler.
pub(crate) struct Served {
    pub(crate) status: u16,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    /// Wait this long before answering (a slow or hanging server).
    pub(crate) delay: Option<std::time::Duration>,
}

/// What [`serve_tls`] asks about each request: the raw request (head, and the
/// body when `content-length` gives its length) in, the reply out.
pub(crate) type Handler = Arc<dyn Fn(&str) -> Served + Send + Sync>;

/// A loopback HTTPS server presenting `leaf`, answering every request (one per
/// connection, `Connection: close`) with the handler `make` builds from the
/// bound address. The engine under [`spawn_tls`] and the stateful [`fake`].
pub(crate) async fn serve_tls<M>(leaf: TestLeaf, make: M) -> SocketAddr
where
    M: FnOnce(SocketAddr) -> Handler,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // Both `ring` and `aws-lc-rs` are reachable in this tree, so rustls refuses
    // to guess a process-level provider for the SERVER side here. Install ring.
    //
    // **What reqwest 0.13 actually does** (`async_impl/client.rs`):
    //
    //     let provider = rustls::crypto::CryptoProvider::get_default()
    //         .map(|arc| arc.clone())
    //         .unwrap_or_else(default_rustls_crypto_provider);
    //
    // So it READS the process default and falls back to aws-lc-rs. Installing
    // ring here therefore DOES affect reqwest clients built afterwards in the
    // same test binary — which makes the client's provider depend on whether any
    // test called `spawn_tls` first. Benign (ring and aws-lc-rs interoperate),
    // and absent from release builds, where nothing installs a default and the
    // client is genuinely aws-lc-rs.
    //
    // `install_default` errors if something got there first, which is fine.
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });

    let certs: Vec<CertificateDer<'static>> = pem_certs(leaf.leaf_pem.as_bytes());
    let key: PrivateKeyDer<'static> = pem_key(leaf.leaf_key_pem.as_bytes());

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("test server TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = make(addr);

    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                // **The head, and the body when `content-length` says how much —
                // before replying.**
                //
                // A single `read` is what an earlier capturing server did, and the
                // review of it found the trap: if the head and the body land in
                // separate segments, the capture holds only the head, and every
                // `contains` assertion over it then passes for the wrong reason.
                //
                // **A chunked body is NOT drained.** With no `content-length`
                // there is nothing to wait for, so this stops after the head.
                // Every request this harness sees is a GET or a reqwest-buffered
                // form and carries a length, but nothing here enforces that, so a
                // future chunked request would be captured short and quietly.
                //
                // Draining also stops the reply being written while the client is
                // still sending, which would make a split request a broken pipe
                // rather than a response.
                let mut raw: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let (head, body) = raw.split_at(split + 4);
                    let want = String::from_utf8_lossy(head).lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    });
                    if want.is_none_or(|want| body.len() >= want) {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&raw).to_string();
                let reply = handler(&req);
                if let Some(delay) = reply.delay {
                    tokio::time::sleep(delay).await;
                }
                let extra: String = reply
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}\r\n"))
                    .collect();
                let head = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: {}\r\n{extra}\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.status,
                    reply.content_type,
                    reply.body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&reply.body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

fn pem_certs(pem: &[u8]) -> Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> {
    // Minimal PEM splitter — avoids another dependency for two blocks.
    decode_pem_blocks(pem, "CERTIFICATE")
        .into_iter()
        .map(Into::into)
        .collect()
}

fn pem_key(pem: &[u8]) -> tokio_rustls::rustls::pki_types::PrivateKeyDer<'static> {
    let der = decode_pem_blocks(pem, "PRIVATE KEY")
        .into_iter()
        .next()
        .expect("a private key block");
    tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(der).into()
}

fn decode_pem_blocks(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(pem);
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(i) = rest.find(&begin) {
        let after = &rest[i + begin.len()..];
        let Some(j) = after.find(&end) else { break };
        let b64: String = after[..j].chars().filter(|c| !c.is_whitespace()).collect();
        out.push(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .expect("valid base64 in test PEM"),
        );
        rest = &after[j + end.len()..];
    }
    out
}

/// One canned reply from the TLS test server.
#[derive(Clone, Debug)]
pub struct TestResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body, sent as `application/json`.
    pub body: String,
    /// Extra response headers.
    pub headers: Vec<(String, String)>,
}

impl TestResponse {
    /// A reply with `status` and `body` and no extra headers.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    /// This reply with one more header.
    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
}

/// A JSON server that records every raw request (head and body, read to
/// `content-length`) and answers each with `reply`. For asserting on the
/// BYTES a client sent — the only assertion that catches a record that is
/// wrong on the way out.
pub async fn serve_json_capturing(
    reply: Vec<u8>,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&log);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut raw: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            let text = loop {
                let Ok(n) = sock.read(&mut chunk).await else {
                    break String::new();
                };
                if n == 0 {
                    break String::from_utf8_lossy(&raw).to_string();
                }
                raw.extend_from_slice(&chunk[..n]);
                let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let (head, body) = raw.split_at(split + 4);
                let want = String::from_utf8_lossy(head).lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                });
                if want.is_none_or(|w| body.len() >= w) {
                    break String::from_utf8_lossy(&raw).to_string();
                }
            };
            sink.lock().unwrap().push(text);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            let _ = sock.write_all(header.as_bytes()).await;
            let _ = sock.write_all(&reply).await;
            let _ = sock.flush().await;
        }
    });
    (format!("http://{addr}"), log)
}

/// [`serve_body`] that also counts requests — for an assertion that a URL
/// was NEVER fetched, which a body alone cannot make.
pub async fn serve_body_counted(
    body: Vec<u8>,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/rss+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            });
        }
    });
    (format!("http://{addr}/"), hits)
}

/// Serve a different body per request, in order, repeating the last.
///
/// **The fixed-body servers cannot test a walk.** `serve_body` answers every
/// request identically, so a paging walk sees the same cursor twice and its
/// repeat-detection guard stops it at two pages. Anything that only happens
/// across pages — a budget accumulating, a cursor advancing — is therefore
/// unreachable with them, which is how a cap that was per-page rather than
/// per-walk once passed an entire suite.
///
/// Each request is a fresh connection (`Connection: close`), so accept order
/// is request order for the sequential walks that use this.
pub async fn serve_bodies_in_sequence(bodies: Vec<Vec<u8>>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    assert!(!bodies.is_empty(), "serve_bodies_in_sequence needs a body");
    let bodies = std::sync::Arc::new(bodies);
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = bodies[i.min(bodies.len() - 1)].clone();
            tokio::spawn(async move {
                // **Drain the whole request head, not one fixed read.** A
                // DPoP-signed XRPC request head measures ~880 bytes, so a
                // single 1024-byte read is within a longer NSID or cursor
                // of leaving bytes unread — and closing with data still in
                // the receive queue makes the kernel send RST instead of
                // FIN, which can discard a response the client has not
                // drained. That surfaces as an intermittent connection
                // reset in a test whose failure would read as a budget bug.
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                // Drain the head, then the body it declares. Stopping at
                // the head is not enough: the sidecar's list call is a POST,
                // so on any platform that does not coalesce head and body
                // into one segment the body stays in the receive queue, and
                // closing on unread bytes is the RST-instead-of-FIN case
                // this loop exists to avoid.
                let mut want: Option<usize> = None;
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            req.extend_from_slice(&buf[..n]);
                            let Some(head_end) = req.windows(4).position(|w| w == b"\r\n\r\n")
                            else {
                                continue;
                            };
                            let head_len = head_end + 4;
                            if want.is_none() {
                                let head = String::from_utf8_lossy(&req[..head_len]);
                                want = Some(
                                    head.lines()
                                        .find_map(|l| {
                                            let (k, v) = l.split_once(':')?;
                                            k.eq_ignore_ascii_case("content-length")
                                                .then(|| v.trim().parse::<usize>().ok())?
                                        })
                                        .unwrap_or(0),
                                );
                            }
                            if req.len() >= head_len + want.unwrap_or(0) {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}/")
}

/// A raw HTTP server on loopback that answers every request with `body`
/// (fixed Content-Length). Returns its `http://127.0.0.1:port/` base URL.
/// Used to exercise [`Fetcher::read_capped`](crate::net::Fetcher::read_capped)
/// against a real reqwest `Response`.
pub async fn serve_body(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let body = body.clone();
            tokio::spawn(async move {
                // Drain the request headers (best-effort) then reply.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}/")
}

/// A raw HTTP server on loopback that answers `/final` with `200 arrived`
/// and **everything else** with `302 Location: /final`. Returns its bound
/// address, so a caller can pin a client to it by address rather than name.
///
/// This is the fixture the two tests below need and that the module did not
/// previously have. Note it returns the `SocketAddr`, not a URL: the whole
/// point is to reach it under a hostname that does not resolve.
pub async fn serve_redirect_to_final() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp = if req.starts_with("GET /final") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\narrived"
                } else {
                    "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    addr
}

/// A [`DnsResolver`](crate::resolve::DnsResolver) that answers from a fixed
/// table and records every name it was asked for. No network.
///
/// A name not in the table has no records (`Ok(None)`). Names are matched
/// exactly, and must be registered fully qualified (with the trailing dot), the
/// form resolution queries; so a query that lost its dot finds nothing and shows
/// up in [`StaticDns::queries`] as the bare name it was.
#[derive(Debug, Default)]
pub struct StaticDns {
    answers: HashMap<String, std::result::Result<crate::resolve::TxtRecords, String>>,
    queries: Mutex<Vec<String>>,
}

impl StaticDns {
    /// A resolver with no records anywhere.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer `fqdn` with `records`: one entry per TXT record, each the record's
    /// character-strings in order. Panics unless `fqdn` ends in `.`.
    pub fn with_txt(mut self, fqdn: &str, records: &[&[&str]]) -> Self {
        assert!(fqdn.ends_with('.'), "register {fqdn:?} fully qualified");
        let records = records
            .iter()
            .map(|chunks| chunks.iter().map(|c| c.as_bytes().to_vec()).collect())
            .collect();
        self.answers.insert(fqdn.to_string(), Ok(records));
        self
    }

    /// Fail every lookup of `fqdn` with `message` — a SERVFAIL, a timeout, a
    /// name that cannot be constructed: anything that is not "no records".
    /// Panics unless `fqdn` ends in `.`.
    pub fn failing(mut self, fqdn: &str, message: &str) -> Self {
        assert!(fqdn.ends_with('.'), "register {fqdn:?} fully qualified");
        self.answers
            .insert(fqdn.to_string(), Err(message.to_string()));
        self
    }

    /// Every name looked up so far, in order.
    pub fn queries(&self) -> Vec<String> {
        self.queries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl crate::resolve::DnsResolver for StaticDns {
    async fn txt(&self, fqdn: &str) -> Result<Option<crate::resolve::TxtRecords>> {
        self.queries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(fqdn.to_string());
        match self.answers.get(fqdn) {
            None => Ok(None),
            Some(Ok(records)) => Ok(Some(records.clone())),
            Some(Err(message)) => Err(anyhow::anyhow!("{message}")),
        }
    }
}

/// A contract suite for the storage seams, for any implementation of
/// [`SessionStore`](crate::store::SessionStore) and
/// [`PendingLoginStore`](crate::store::PendingLoginStore).
///
/// calamus runs it against [`crate::store::memory`]; an implementation over a
/// database (FeatherReader's SQLite store) runs the same functions against
/// its own, so both are held to one definition of what the refresh and
/// sign-out races rely on. Each function needs an EMPTY store, and panics with
/// the broken rule's name on the first violation.
///
/// What it pins, from FeatherReader's `store.rs`:
///
/// * a session round-trips, and `put` replaces (re-login is an upsert);
/// * a [`Version`](crate::store::SessionStore::Version) is the row as read, and
///   ANY later write changes it, even one storing identical values;
/// * `update_if_unchanged` writes only over the version it was given: false
///   (and nothing written) after a concurrent rewrite, and false (no
///   resurrection) after a delete;
/// * `delete_if_unchanged` deletes only the version that was read;
/// * a pending login's `take` is single-use, refuses a row at or past its
///   expiry (and removes it anyway), and a second `put` under one `state` is
///   refused rather than replacing the first.
pub mod store_contract {
    use crate::client_auth::AuthMethod;
    use crate::store::{PendingLogin, PendingLoginStore, Session, SessionStore};

    const NOW: i64 = 1_700_000_000;
    const SUB: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const OTHER_SUB: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

    /// A session whose EVERY field derives from `tag`, so a store that writes
    /// only some columns on a rewrite (only the tokens, or keeps the old key,
    /// issuer, audience or expiry) fails the equality checks below. The tag
    /// `"ours"` has no expiry, so a `NULL`/`None` write is exercised too.
    fn session(sub: &str, tag: &str) -> Session {
        let salt: i64 = tag.bytes().map(i64::from).sum::<i64>() * 7 + tag.len() as i64;
        Session {
            sub: sub.into(),
            issuer: format!("https://auth-{tag}.example.com"),
            aud: format!("https://pds-{tag}.example.com"),
            dpop_key_jwk: format!(r#"{{"kty":"EC","d":"{tag}"}}"#),
            access_token: format!("access-for-{tag}"),
            refresh_token: tag.into(),
            token_type: format!("DPoP-{tag}"),
            granted_scope: format!("atproto scope-{tag}"),
            expires_at: (tag != "ours").then_some(NOW + 3600 + salt),
        }
    }

    fn pending_login(state: &str, expires_at: i64) -> PendingLogin {
        PendingLogin {
            state: state.into(),
            browser_binding_hash: "binding-hash".into(),
            pkce_verifier: "verifier".into(),
            dpop_key_jwk: r#"{"kty":"EC","d":"k"}"#.into(),
            issuer: "https://auth.example.com".into(),
            pds_url: "https://pds.example.com".into(),
            did: SUB.into(),
            auth_method: AuthMethod::PrivateKeyJwt,
            auth_kid: Some("client-kid".into()),
            // Not derivable from the redirect: a store that drops it, or
            // rebuilds it from another column, fails the round trip.
            client_id: "https://client-id.example/oauth/client-metadata.json".into(),
            redirect_uri: "https://client.example/oauth/callback".into(),
            requested_scope: "atproto".into(),
            request_uri: "urn:ietf:params:oauth:request_uri:x".into(),
            app_return_to: Some("/after".into()),
            expires_at,
        }
    }

    /// Run every [`SessionStore`] rule against `store`, which must be empty.
    pub async fn sessions<S: SessionStore>(store: &S) {
        // Absent.
        assert_eq!(store.get(SUB).await.unwrap(), None, "absent: get");
        assert!(
            store.get_versioned(SUB).await.unwrap().is_none(),
            "absent: get_versioned"
        );
        assert!(
            !store.delete(SUB).await.unwrap(),
            "absent: delete reported a row"
        );

        // Round trip, and both reads agree.
        let first = session(SUB, "r1");
        store.put(&first).await.unwrap();
        assert_eq!(
            store.get(SUB).await.unwrap(),
            Some(first.clone()),
            "round trip"
        );
        let (read, v1) = store.get_versioned(SUB).await.unwrap().expect("round trip");
        assert_eq!(read, first, "get_versioned returned a different session");
        let (_, v1_again) = store.get_versioned(SUB).await.unwrap().unwrap();
        assert!(
            v1 == v1_again,
            "two reads of an unwritten row disagree on its version"
        );

        // `put` replaces: a re-login is an upsert, not a refused insert.
        let relogin = session(SUB, "r2");
        store.put(&relogin).await.unwrap();
        assert_eq!(
            store.get(SUB).await.unwrap(),
            Some(relogin.clone()),
            "put did not replace"
        );
        let (_, v2) = store.get_versioned(SUB).await.unwrap().unwrap();
        assert!(v1 != v2, "a rewrite left the version unchanged");

        // update_if_unchanged: false after a concurrent rewrite, nothing written.
        let ours = session(SUB, "ours");
        assert!(
            !store.update_if_unchanged(&ours, &v1).await.unwrap(),
            "update_if_unchanged wrote over a row rewritten since its version was read"
        );
        assert_eq!(
            store.get(SUB).await.unwrap(),
            Some(relogin.clone()),
            "a refused update_if_unchanged still changed the row"
        );

        // ...true over the version it was given, and that write is a new version.
        assert!(
            store.update_if_unchanged(&ours, &v2).await.unwrap(),
            "update_if_unchanged refused the current version"
        );
        assert_eq!(
            store.get(SUB).await.unwrap(),
            Some(ours.clone()),
            "update not stored"
        );
        let (_, v3) = store.get_versioned(SUB).await.unwrap().unwrap();
        assert!(v3 != v2, "update_if_unchanged left the version unchanged");
        assert!(
            !store
                .update_if_unchanged(&session(SUB, "again"), &v2)
                .await
                .unwrap(),
            "a version was usable twice"
        );

        // Any write changes the version, even one storing identical values.
        store.put(&ours).await.unwrap();
        let (_, v4) = store.get_versioned(SUB).await.unwrap().unwrap();
        assert!(
            v4 != v3,
            "rewriting identical values left the version unchanged"
        );
        assert!(
            !store.delete_if_unchanged(SUB, &v3).await.unwrap(),
            "delete_if_unchanged deleted a row rewritten (with identical values) since"
        );

        // delete_if_unchanged: only the version that was read.
        assert!(
            store.get(SUB).await.unwrap().is_some(),
            "a refused delete_if_unchanged deleted"
        );
        assert!(
            store.delete_if_unchanged(SUB, &v4).await.unwrap(),
            "delete_if_unchanged refused the current version"
        );
        assert_eq!(
            store.get(SUB).await.unwrap(),
            None,
            "delete_if_unchanged left the row"
        );
        assert!(
            !store.delete_if_unchanged(SUB, &v4).await.unwrap(),
            "delete_if_unchanged reported deleting an absent row"
        );

        // No resurrection: an update over a deleted row writes nothing.
        assert!(
            !store.update_if_unchanged(&ours, &v4).await.unwrap(),
            "update_if_unchanged reported writing a deleted row"
        );
        assert_eq!(
            store.get(SUB).await.unwrap(),
            None,
            "update_if_unchanged RESURRECTED a deleted session"
        );

        // A version is never reused for a subject, even across a delete and a
        // re-insert of IDENTICAL values (ABA): a store numbering writes per row
        // from 1 would hand the re-inserted row the deleted row's version.
        let original = session(SUB, "aba");
        store.put(&original).await.unwrap();
        let (_, before) = store.get_versioned(SUB).await.unwrap().unwrap();
        assert!(store.delete(SUB).await.unwrap());
        store.put(&original).await.unwrap();
        assert!(
            !store
                .update_if_unchanged(&session(SUB, "stale-writer"), &before)
                .await
                .unwrap(),
            "update_if_unchanged accepted a version from before a delete and re-insert (ABA)"
        );
        assert!(
            !store.delete_if_unchanged(SUB, &before).await.unwrap(),
            "delete_if_unchanged accepted a version from before a delete and re-insert (ABA)"
        );
        assert_eq!(
            store.get(SUB).await.unwrap(),
            Some(original),
            "a stale version changed the re-inserted row"
        );
        assert!(store.delete(SUB).await.unwrap());

        // Subjects are independent, and delete reports what it did.
        store.put(&session(SUB, "a")).await.unwrap();
        store.put(&session(OTHER_SUB, "b")).await.unwrap();
        let (_, other_version) = store.get_versioned(OTHER_SUB).await.unwrap().unwrap();
        assert!(
            store.delete(SUB).await.unwrap(),
            "delete did not report the row"
        );
        assert!(
            !store.delete(SUB).await.unwrap(),
            "delete reported a row twice"
        );
        assert_eq!(
            store.get(OTHER_SUB).await.unwrap(),
            Some(session(OTHER_SUB, "b")),
            "deleting one subject touched another"
        );
        assert!(
            !store
                .update_if_unchanged(&session(SUB, "x"), &other_version)
                .await
                .unwrap(),
            "one subject's version updated another subject's row"
        );
        assert_eq!(store.get(SUB).await.unwrap(), None);
        assert!(store.delete(OTHER_SUB).await.unwrap());
    }

    /// `take` is atomic under real parallelism: `tasks` spawned takes of one
    /// state, released together, for `rounds` rounds; exactly one wins each
    /// round. Needs a multi-threaded runtime with at least two workers
    /// (`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` or more),
    /// or the takes never overlap; `store` must be empty. A losing take must
    /// return `Ok(None)`: an error fails the step, saying so. `tasks` must be
    /// at least 2 and `rounds` at least 1, or the step refuses to run.
    pub async fn pending_take_is_atomic<P: PendingLoginStore + 'static>(
        store: std::sync::Arc<P>,
        tasks: usize,
        rounds: usize,
    ) {
        assert_multi_thread("pending_take_is_atomic");
        assert_a_race("pending_take_is_atomic", tasks, rounds);
        for round in 0..rounds {
            let state = format!("s-atomic-{round}");
            store.put(&pending_login(&state, NOW + 600)).await.unwrap();
            let start = std::sync::Arc::new(tokio::sync::Barrier::new(tasks));
            let handles: Vec<_> = (0..tasks)
                .map(|_| {
                    let (store, start, state) = (store.clone(), start.clone(), state.clone());
                    tokio::spawn(async move {
                        start.wait().await;
                        store.take(&state, NOW).await
                    })
                })
                .collect();
            let mut winners = 0;
            for handle in handles {
                let taken = race_answer(
                    "pending_take_is_atomic",
                    "take",
                    "Ok(None)",
                    handle.await.unwrap(),
                );
                winners += usize::from(taken.is_some());
            }
            assert_eq!(winners, 1, "round {round}: {winners} concurrent takes won");
        }
    }

    /// A parallelism step on a current-thread runtime passes without testing
    /// anything: its tasks never overlap. Nor on a multi-thread runtime with
    /// ONE worker (`worker_threads = 1`): the spawned tasks all run on that
    /// thread, interleaved only at `.await`s. So the step requires at least two
    /// workers, read from `Handle::metrics().num_workers()` (stable since
    /// tokio 1.39; this crate pins 1.45+). The barrier each round starts its
    /// tasks on lines them up, but cannot by itself prove they run at once: a
    /// barrier releases cooperatively-scheduled tasks on one thread too.
    fn assert_multi_thread(step: &str) {
        let handle = tokio::runtime::Handle::current();
        assert_eq!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread,
            "{step} needs a multi-thread runtime (#[tokio::test(flavor = \"multi_thread\")]); \
             on a current-thread one it passes vacuously"
        );
        let workers = handle.metrics().num_workers();
        assert!(
            workers >= 2,
            "{step} needs at least two worker threads (#[tokio::test(flavor = \
             \"multi_thread\", worker_threads = 2)] or more), got {workers}; on one its \
             tasks never run at once and it passes vacuously"
        );
    }

    /// A race needs at least two racers and at least one round: one task
    /// never contends, and zero rounds run nothing, so either passes for any
    /// store.
    fn assert_a_race(step: &str, tasks: usize, rounds: usize) {
        assert!(
            tasks >= 2,
            "{step}: a race needs at least two tasks, got {tasks}; with one it passes vacuously"
        );
        assert!(
            rounds >= 1,
            "{step}: needs at least one round, got {rounds}; with none it tests nothing"
        );
    }

    /// A store's answer to one racing call, or a panic that says what is
    /// wrong when it errored: a lost race is an answer (`Ok(false)`, or
    /// `Ok(None)` for `take`), never an error.
    ///
    /// **Only a failure that PROVES another writer committed may be reported
    /// as the loss**: e.g. Postgres `40001` ("could not serialize access due
    /// to concurrent update") from a version-guarded `UPDATE`/`DELETE` under
    /// `REPEATABLE READ` or `SERIALIZABLE`, which is raised exactly because
    /// the row was changed by a committed transaction. **Under
    /// `SERIALIZABLE`, the other `40001` ("could not serialize access due to
    /// read/write dependencies among transactions") proves nothing**: SSI can
    /// raise it as a false positive for a row nobody changed, so retry the
    /// transaction or return it as an error. Under `READ COMMITTED` a
    /// version-guarded `UPDATE`/`DELETE` that lost affects 0 rows, which is
    /// the plain `Ok(false)`. **A lock or busy timeout (SQLite
    /// `SQLITE_BUSY`, `database is locked`, a Postgres lock timeout or
    /// deadlock) proves nothing** about the row: retry it inside the store,
    /// or return it as an error. Reporting it as `Ok(false)` tells the
    /// refresh path that another writer replaced the row, and it then
    /// revokes the refresh token the server has just rotated to, which may be
    /// the grant's only live one: a briefly locked database logs the user
    /// out. An error makes the refresh fail its request and revoke nothing.
    /// Here, under real contention, a correct store answers every racing call;
    /// an error is a store that does neither.
    fn race_answer<T>(step: &str, call: &str, lost: &str, answer: anyhow::Result<T>) -> T {
        match answer {
            Ok(answer) => answer,
            Err(err) => panic!(
                "{step}: {call} returned an error under contention ({err:#}). A call that \
                 loses the race must report {lost}, not an error. Map a failure to the loss \
                 ONLY when it proves another writer committed (e.g. Postgres 40001 \
                 \"could not serialize access due to concurrent update\" from a \
                 version-guarded UPDATE under REPEATABLE READ or SERIALIZABLE; SSI's \
                 \"read/write dependencies\" 40001 can be a false positive and must be \
                 retried or returned as an error); a lock or busy timeout (SQLITE_BUSY) proves nothing and must be \
                 retried inside the store (or, outside a race, returned as an error), never \
                 reported as {lost}"
            ),
        }
    }

    /// The conditional writes are atomic under real parallelism: each round
    /// stores a row, reads its version once, and releases `tasks` spawned
    /// writers together, all presenting that version. Three races, `rounds`
    /// rounds each, and exactly one writer wins every round:
    ///
    /// * `update_if_unchanged` against `update_if_unchanged` (the winner's
    ///   session is what is stored);
    /// * `delete_if_unchanged` against `delete_if_unchanged` (the row is gone);
    /// * `update_if_unchanged` against `delete_if_unchanged`, half each (the
    ///   row is the winning update's, or gone if a delete won).
    ///
    /// A store that checks the version in one statement (or lock scope) and
    /// writes in another lets two writers both see the version they read and
    /// both report success: two refreshes each storing their own rotation, or
    /// a refresh and a sign-out both "winning", which is a resurrection. Needs
    /// a multi-threaded runtime with at least two workers; `store` must be
    /// empty and is left empty. A losing write must return `Ok(false)`: an
    /// error fails the step, saying so. `Ok(false)` is reserved for a row that
    /// really changed: a lock or busy timeout must be retried inside the
    /// store, never reported as `Ok(false)` (see the panic's guidance).
    /// `tasks` must be at least 2 and `rounds` at least 1.
    pub async fn sessions_conditional_writes_are_atomic<S: SessionStore + 'static>(
        store: std::sync::Arc<S>,
        tasks: usize,
        rounds: usize,
    ) {
        assert_multi_thread("sessions_conditional_writes_are_atomic");
        assert_a_race("sessions_conditional_writes_are_atomic", tasks, rounds);
        for (race, label) in ["update/update", "delete/delete", "update/delete"]
            .into_iter()
            .enumerate()
        {
            for round in 0..rounds {
                store.put(&session(SUB, "race-base")).await.unwrap();
                let (_, version) = store.get_versioned(SUB).await.unwrap().unwrap();
                let start = std::sync::Arc::new(tokio::sync::Barrier::new(tasks));
                let handles: Vec<_> = (0..tasks)
                    .map(|writer| {
                        let (store, start, version) =
                            (store.clone(), start.clone(), version.clone());
                        let update = match race {
                            0 => true,
                            1 => false,
                            _ => writer % 2 == 0,
                        };
                        tokio::spawn(async move {
                            let mine = session(SUB, &format!("race-{writer}"));
                            start.wait().await;
                            let won = if update {
                                store.update_if_unchanged(&mine, &version).await
                            } else {
                                store.delete_if_unchanged(SUB, &version).await
                            };
                            (won, update.then_some(mine))
                        })
                    })
                    .collect();
                let mut winners = Vec::new();
                for handle in handles {
                    let (won, wrote) = handle.await.unwrap();
                    let call = if wrote.is_some() {
                        "update_if_unchanged"
                    } else {
                        "delete_if_unchanged"
                    };
                    let won = race_answer(
                        &format!("sessions_conditional_writes_are_atomic, {label}, round {round}"),
                        call,
                        "Ok(false)",
                        won,
                    );
                    if won {
                        winners.push(wrote);
                    }
                }
                assert_eq!(
                    winners.len(),
                    1,
                    "{label}, round {round}: {} conditional writes on one version won",
                    winners.len()
                );
                let stored = store.get(SUB).await.unwrap();
                assert_eq!(
                    stored, winners[0],
                    "{label}, round {round}: the row is not the winning write's"
                );
                store.delete(SUB).await.unwrap();
            }
        }
    }

    /// Run every [`PendingLoginStore`] rule against `store`, which must be
    /// empty.
    pub async fn pending<P: PendingLoginStore>(store: &P) {
        assert_eq!(
            store.take("unknown", NOW).await.unwrap(),
            None,
            "absent: take"
        );

        // Round trip, single use.
        let live = pending_login("s-live", NOW + 600);
        store.put(&live).await.unwrap();
        assert_eq!(
            store.take("s-live", NOW).await.unwrap(),
            Some(live.clone()),
            "round trip"
        );
        assert_eq!(
            store.take("s-live", NOW).await.unwrap(),
            None,
            "a pending login was taken twice"
        );

        // Two takes racing: exactly one wins.
        store
            .put(&pending_login("s-race", NOW + 600))
            .await
            .unwrap();
        let (a, b) = tokio::join!(store.take("s-race", NOW), store.take("s-race", NOW));
        let winners = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|t| t.is_some())
            .count();
        assert_eq!(winners, 1, "concurrent takes of one state: {winners} won");

        // Expired AT `expires_at`, and removed regardless.
        store.put(&pending_login("s-edge", NOW)).await.unwrap();
        assert_eq!(
            store.take("s-edge", NOW).await.unwrap(),
            None,
            "a row was accepted at its expiry"
        );
        assert_eq!(
            store.take("s-edge", NOW - 1).await.unwrap(),
            None,
            "an expired take left the row behind"
        );
        store.put(&pending_login("s-just", NOW + 1)).await.unwrap();
        assert!(
            store.take("s-just", NOW).await.unwrap().is_some(),
            "a row was refused a second before its expiry"
        );

        // A second put under a pending state is refused, and the first stands.
        let first = pending_login("s-dup", NOW + 600);
        store.put(&first).await.unwrap();
        let mut second = pending_login("s-dup", NOW + 600);
        second.issuer = "https://evil.example".into();
        assert!(
            store.put(&second).await.is_err(),
            "a put replaced a pending login under the same state"
        );
        assert_eq!(
            store.take("s-dup", NOW).await.unwrap(),
            Some(first),
            "a refused put changed the pending login"
        );

        // States are independent.
        store.put(&pending_login("s-one", NOW + 600)).await.unwrap();
        store.put(&pending_login("s-two", NOW + 600)).await.unwrap();
        assert!(store.take("s-one", NOW).await.unwrap().is_some());
        assert!(
            store.take("s-two", NOW).await.unwrap().is_some(),
            "taking one state consumed another"
        );
    }
}

/// Stores whose operations move tokio's clock forward, for the tests that pin
/// WHEN a proof, an assertion or an expiry is minted. The clock is paused only
/// for the advance and resumed at once, so it never spans network I/O (where
/// auto-advance would fire reqwest's timeouts).
#[cfg(test)]
pub(crate) mod slow {
    use std::time::Duration;

    use anyhow::Result;

    use crate::store::memory::{MemoryNonces, MemoryPendingLogins};
    use crate::store::{NonceStore, PendingLogin, PendingLoginStore};

    /// Advance tokio's clock by `by`, without leaving it paused.
    pub(crate) async fn advance(by: Duration) {
        if by.is_zero() {
            return;
        }
        tokio::time::pause();
        tokio::time::advance(by).await;
        tokio::time::resume();
    }

    /// [`MemoryNonces`] whose `get` advances the clock by `on_get` and whose
    /// `put` advances it by `on_put` (after storing).
    #[derive(Default)]
    pub(crate) struct SlowNonces {
        pub(crate) inner: MemoryNonces,
        pub(crate) on_get: Duration,
        pub(crate) on_put: Duration,
    }

    impl NonceStore for SlowNonces {
        async fn get(&self, origin: &str) -> Result<Option<String>> {
            let got = self.inner.get(origin).await;
            advance(self.on_get).await;
            got
        }

        async fn put(&self, origin: &str, nonce: &str, now: i64) -> Result<()> {
            self.inner.put(origin, nonce, now).await?;
            advance(self.on_put).await;
            Ok(())
        }
    }

    /// [`MemoryPendingLogins`] whose `take` advances the clock by `on_take`.
    #[derive(Default)]
    pub(crate) struct SlowPending {
        pub(crate) inner: MemoryPendingLogins,
        pub(crate) on_take: Duration,
    }

    impl PendingLoginStore for SlowPending {
        async fn put(&self, login: &PendingLogin) -> Result<()> {
            self.inner.put(login).await
        }

        async fn take(&self, state: &str, now: i64) -> Result<Option<PendingLogin>> {
            let taken = self.inner.take(state, now).await;
            advance(self.on_take).await;
            taken
        }
    }
}
