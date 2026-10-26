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
    // Routes are built from the bound address: the documents have to name their
    // own port, and the port is not known until the listener exists.
    let routes = build_routes(addr);
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let hits: Arc<Mutex<HashMap<String, usize>>> = Default::default();

    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let routes = routes.clone();
            let sink = Arc::clone(&sink);
            let hits = Arc::clone(&hits);
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
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                sink.lock().unwrap().push(req);
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
                let extra: String = reply
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}\r\n"))
                    .collect();
                let (status, body) = (reply.status, reply.body);
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, log)
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
