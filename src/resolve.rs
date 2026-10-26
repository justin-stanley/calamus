//! Turning what a user typed into a DID, a DID document, and a PDS.
//!
//! The I/O half of [`crate::identity`], which holds the decisions. Split that
//! way because the decisions are where the security properties live and they
//! are testable; this is sequencing and network calls, which are not.
//!
//! **DNS takes precedence over HTTP.** The handle spec: *"When both methods
//! return results, the DNS TXT result should be preferred."* It is not a
//! tie-break rule in practice — a real handle was found during the live spike
//! whose `/.well-known/atproto-did` returns 404 and which resolves by TXT
//! alone, so an HTTP-first implementation simply fails on it.
//!
//! **DNS goes through a seam, [`DnsResolver`].** [`SystemResolver`] (the default
//! `dns` feature) is hickory with the host's own configuration;
//! `calamus::testing::StaticDns` is a fake for tests, so nothing in the default
//! test run touches the network.
//!
//! Ported from FeatherReader `src/oauth/resolve.rs`, where the resolver was a
//! concrete `hickory_resolver::TokioResolver`.

use std::future::Future;

use anyhow::{Context as _, Result};

use crate::net::Fetcher;
use crate::{fetch, identity};

/// A resolved account: who they are and where their repo lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAccount {
    /// The account's DID.
    pub did: String,
    /// The PDS the DID document names, validated by
    /// [`identity::pds_endpoint`].
    pub pds_url: String,
    /// The handle, only when it was verified bidirectionally. `None` for a
    /// DID-first login whose handle did not round-trip — it must not be
    /// displayed as though it were confirmed.
    pub handle: Option<String>,
}

/// TXT records as a [`DnsResolver`] returns them: one entry per record, each the
/// record's character-strings in order, unjoined.
pub type TxtRecords = Vec<Vec<Vec<u8>>>;

/// The TXT lookups handle resolution needs, as a seam.
///
/// **The contract is the security property, so read it before implementing:**
///
/// * `fqdn` is fully qualified (it ends in `.`). Query it **as given**: never
///   apply a search list, or whoever controls a search domain answers for every
///   handle without a TXT record of its own (see `txt_query_name`).
/// * `Ok(None)` means **only** that the name has no such records (NXDOMAIN, or
///   no TXT at the name). It is the one answer that lets resolution fall
///   through to the well-known lookup.
/// * Every other failure — SERVFAIL, a timeout, a refused connection, a name
///   that cannot be constructed — must be `Err`. Reporting it as `Ok(None)` lets
///   an attacker who can induce a resolver error choose the weaker mechanism.
/// * `Ok(Some(records))`: one entry per TXT **record**, each the record's
///   character-strings in order, unjoined. [`identity::join_txt_chunks`] is the
///   joiner, so a long record split into chunks stays one value.
///
/// The future must be `Send`, so resolution can be spawned on a multi-threaded
/// runtime. An `async fn` in the impl satisfies this when its body is `Send`.
pub trait DnsResolver: Send + Sync {
    /// Look up the TXT records at `fqdn`. See the trait docs for the contract.
    fn txt(&self, fqdn: &str) -> impl Future<Output = Result<Option<TxtRecords>>> + Send;
}

/// [`DnsResolver`] over hickory, configured from the host's own resolver
/// configuration (`/etc/resolv.conf`, or the platform's equivalent).
#[cfg(feature = "dns")]
pub struct SystemResolver(hickory_resolver::TokioResolver);

#[cfg(feature = "dns")]
impl std::fmt::Debug for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemResolver").finish_non_exhaustive()
    }
}

#[cfg(feature = "dns")]
impl SystemResolver {
    /// Build the resolver from the host's own configuration.
    ///
    /// FeatherReader's `resolve::resolver()`. Reads the configuration; issues no
    /// query.
    pub fn from_system_config() -> Result<Self> {
        let builder = hickory_resolver::TokioResolver::builder_tokio()
            .context("reading the system DNS configuration")?;
        Ok(Self(builder.build().context("building the DNS resolver")?))
    }
}

#[cfg(feature = "dns")]
impl DnsResolver for SystemResolver {
    async fn txt(&self, fqdn: &str) -> Result<Option<TxtRecords>> {
        let name = system_query_name(fqdn)?;
        let lookup = match self.0.txt_lookup(name).await {
            Ok(lookup) => lookup,
            // ONLY "no records" is absence. Everything else — SERVFAIL, timeout,
            // refused — is a failure and must NOT fall through to the well-known
            // path: an attacker who can induce a resolver error would otherwise
            // choose which of the two mechanisms answers, and the HTTP one is the
            // weaker.
            Err(err) if is_no_records(&err) => return Ok(None),
            Err(err) => return Err(anyhow::Error::new(err)),
        };
        // One entry per RECORD, its character-strings unjoined (the caller joins
        // them). Flattening them into separate records would split a long DID in
        // half.
        Ok(Some(
            lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt),
                    _ => None,
                })
                .map(|txt| txt.txt_data.iter().map(|c| c.to_vec()).collect())
                .collect(),
        ))
    }
}

/// The hickory `Name` [`SystemResolver`] queries for `fqdn`: refused unless it
/// is fully qualified, because hickory's `build_names` appends the search list
/// to any name that is not (`is_fqdn()` is its only short-circuit). Name
/// construction also refuses a name over the 255-byte DNS limit, before any
/// query.
#[cfg(feature = "dns")]
fn system_query_name(fqdn: &str) -> Result<hickory_resolver::proto::rr::Name> {
    let name = hickory_resolver::proto::rr::Name::from_utf8(fqdn)
        .with_context(|| format!("{fqdn:?} is not a DNS name"))?;
    if !name.is_fqdn() {
        anyhow::bail!(
            "{fqdn:?} is not fully qualified; refusing a lookup the search list would expand"
        );
    }
    Ok(name)
}

/// Whether a resolver error means "this name has no such record", as opposed to
/// a failure to find out which.
#[cfg(feature = "dns")]
fn is_no_records(err: &hickory_resolver::net::NetError) -> bool {
    matches!(
        err,
        hickory_resolver::net::NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(_))
    )
}

/// The name to query, **fully qualified**.
///
/// The trailing dot is load-bearing. hickory's `build_names` short-circuits only
/// on `is_fqdn()`; without it, the host's `search` domains are appended and
/// `_atproto.victim.example` is also queried as
/// `_atproto.victim.example.<search-domain>`. Whoever controls that domain can
/// then answer for any handle that has no TXT record of its own — and because
/// DNS is tried first, the well-known lookup never runs, so the substitution is
/// total. Kubernetes always sets a search domain; so do most LANs.
///
/// Node's `dns.resolveTxt` issues the name as given (c-ares does not apply the
/// search list), which is why the reference implementation never needed this.
fn txt_query_name(handle: &str) -> String {
    format!("_atproto.{}.", handle.trim_end_matches('.'))
}

/// Look up `_atproto.<handle>` and return the DID it claims.
///
/// `Ok(None)` means no usable record, which falls through to the well-known
/// lookup. An error means records exist but are unusable — two different `did=`
/// values, say — or that the resolver failed; neither may fall through, because
/// resolving a handle two ways and taking whichever answers is how you resolve
/// to the wrong account.
pub async fn did_from_dns(dns: &impl DnsResolver, handle: &str) -> Result<Option<String>> {
    let name = txt_query_name(handle);
    // ONLY "no records" is absence (the `DnsResolver` contract); every resolver
    // error propagates.
    let Some(raw) = dns
        .txt(&name)
        .await
        .with_context(|| format!("resolving the {name} TXT record"))?
    else {
        return Ok(None);
    };

    // One joined value per RECORD. A record's character-strings concatenate;
    // flattening them into separate records would split a long DID in half.
    let records: Vec<String> = raw
        .iter()
        .map(|chunks| {
            let chunks: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
            identity::join_txt_chunks(&chunks)
        })
        .collect();

    identity::did_from_txt_records(handle, &records)
        .with_context(|| format!("reading the {name} TXT record"))
}

/// Look up `/.well-known/atproto-did`.
///
/// The one fetch in this module where redirects ARE permitted: the handle spec
/// allows them explicitly, unlike the metadata and DID documents.
async fn did_from_well_known(fetcher: &Fetcher, handle: &str) -> Result<String> {
    let url = format!("https://{handle}/.well-known/atproto-did");
    let response = fetcher
        .get_without_hop_policy(&url, &[])
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = response.status().as_u16();
    // A 4xx: nothing is served for that handle (a typo, or no such account),
    // typed so a login form can say so. Except 408 and 429 (transient: try
    // again later) and 403 (a bot challenge in front of a custom-domain
    // handle is common, and says nothing about the handle). Those, and
    // anything else (a 5xx, a 3xx it would not follow), are not evidence of
    // absence, and stay untyped.
    if is_no_did_status(status) {
        return Err(identity::no_did(
            handle,
            crate::error::NoDidReason::WellKnownStatus { url, status },
        ));
    }
    if status != 200 {
        anyhow::bail!("{url} returned status {status}");
    }
    let body = fetcher.read_capped(response).await?;
    identity::did_from_well_known(handle, &String::from_utf8_lossy(&body))
        .with_context(|| format!("reading {url}"))
}

/// Whether a `/.well-known/atproto-did` status says the handle names no DID:
/// a `4xx` other than `403`, `408` and `429`.
fn is_no_did_status(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 403 | 408 | 429)
}

/// Resolve a handle to a DID: DNS first, then well-known.
pub async fn did_for_handle(
    dns: &impl DnsResolver,
    fetcher: &Fetcher,
    handle: &str,
) -> Result<String> {
    let found = did_from_dns(dns, handle).await?;
    prefer_dns(found, || did_from_well_known(fetcher, handle)).await
}

/// Apply the precedence rule: DNS wins, and the well-known lookup runs **only**
/// when DNS returned no record at all.
///
/// `well_known` is a closure rather than a value so the property that matters is
/// observable: that it is never CALLED when DNS answered. With the two lookups
/// inline, swapping their order passed the whole suite — the rule was documented
/// in the module header and pinned by nothing.
///
/// Note what the caller has already done: [`did_from_dns`] returns `Err` for a
/// resolver FAILURE and `Ok(None)` only for a genuine absence, so the `?` above
/// means a SERVFAIL never reaches this fallback. An attacker who can induce a
/// resolver error must not get to choose the weaker mechanism.
pub async fn prefer_dns<F, Fut>(dns: Option<String>, well_known: F) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<String>>,
{
    match dns {
        Some(did) => Ok(did),
        None => well_known().await,
    }
}

/// Fetch and validate a DID document.
pub async fn did_document(
    fetcher: &Fetcher,
    did: &str,
    plc_directory: &str,
) -> Result<serde_json::Value> {
    let url = identity::did_document_url(did, plc_directory)?;
    let document = fetch::get_json(fetcher, &url, fetch::DID_JSON).await?;
    identity::validate_did_document(&document, did)?;
    Ok(document)
}

/// Resolve whatever the user typed into an account.
///
/// From a HANDLE, the DID document must claim that handle back — the spec calls
/// this mandatory, and without it whoever controls a DNS name can point it at
/// any DID at all.
///
/// From a DID, the document's claimed handle is only trustworthy if re-resolving
/// it returns the same DID; when it does not, the handle is reported as `None`
/// rather than displayed beside an account it may not belong to.
pub async fn resolve(
    dns: &impl DnsResolver,
    fetcher: &Fetcher,
    subject: &str,
    plc_directory: &str,
) -> Result<ResolvedAccount> {
    if identity::is_atproto_did(subject) {
        let document = did_document(fetcher, subject, plc_directory).await?;
        // The reverse round trip is I/O; deciding what it MEANS is not.
        let reverse = match identity::declared_handle(&document) {
            Some(handle) => did_for_handle(dns, fetcher, &handle).await.ok(),
            None => None,
        };
        return account_from_did(&document, subject, reverse.as_deref());
    }

    let handle = identity::normalize_handle(subject)?;
    let did = did_for_handle(dns, fetcher, &handle).await?;
    let document = did_document(fetcher, &did, plc_directory).await?;
    account_from_handle(&document, &handle, &did)
}

/// The decision half of a HANDLE-first resolution.
///
/// Split out from the I/O so it can be tested: with the fetching inline, a
/// mutation that dropped the `?` from `verify_handle_claim` — deleting the
/// verification the spec calls mandatory — passed the entire suite, because
/// every test of that rule sat one layer below on `verify_handle_claim` itself
/// and nothing proved `resolve` called it.
pub fn account_from_handle(
    document: &serde_json::Value,
    handle: &str,
    did: &str,
) -> Result<ResolvedAccount> {
    // MANDATORY. Without it, whoever controls a DNS name can point it at any
    // DID at all and we would serve that account under this handle.
    identity::verify_handle_claim(document, handle)?;
    Ok(ResolvedAccount {
        pds_url: identity::pds_endpoint(document, did)?,
        did: did.to_string(),
        handle: Some(handle.to_string()),
    })
}

/// The decision half of a DID-first resolution.
///
/// `reverse` is the DID that re-resolving the document's claimed handle
/// returned, or `None` if there was no claim or the lookup failed. The handle is
/// reported ONLY when that round trip came back to the same DID — a document can
/// claim any handle it likes, and only the handle's own DNS or well-known record
/// can confirm it.
pub fn account_from_did(
    document: &serde_json::Value,
    did: &str,
    reverse: Option<&str>,
) -> Result<ResolvedAccount> {
    let claimed = identity::declared_handle(document);
    let handle = match (&claimed, reverse) {
        (Some(_), Some(back)) if back == did => claimed.clone(),
        // Claimed but unconfirmed, or never claimed: absent, not "probably
        // right". An unverified handle displayed beside an account is a lie
        // with a UI around it.
        _ => None,
    };
    Ok(ResolvedAccount {
        pds_url: identity::pds_endpoint(document, did)?,
        did: did.to_string(),
        handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::StaticDns;

    /// **The query name must be FULLY QUALIFIED.**
    ///
    /// Without the trailing dot, hickory appends the host's `search` domains
    /// (`build_names` short-circuits only on `is_fqdn()`), so
    /// `_atproto.victim.example` is ALSO queried as
    /// `_atproto.victim.example.<search-domain>`. Whoever controls that domain
    /// then answers for any handle lacking a TXT record — and since DNS is tried
    /// first, the well-known lookup never runs. Kubernetes always has a search
    /// domain; so do most corporate and home LANs.
    ///
    /// Node's `dns.resolveTxt` goes through c-ares, which issues the name as
    /// given, so the reference implementation never had this and the port
    /// acquired it silently.
    #[test]
    fn the_txt_query_name_is_fully_qualified() {
        let name = txt_query_name("alice.example.com");
        assert!(
            name.ends_with('.'),
            "not an FQDN, so the DNS search list applies: {name}"
        );
        assert_eq!(name, "_atproto.alice.example.com.");
        assert!(!name.contains(".."), "double dot in {name}");
    }

    /// A handle that does not exist must be reported as absent, not as an
    /// error — the well-known route is the documented fallback and has to be
    /// reachable.
    ///
    /// FeatherReader asked the system resolver for this name over the network;
    /// here the resolver seam answers "no records", which is what that lookup
    /// returned. `SystemResolver`'s own mapping of hickory's `NoRecordsFound` to
    /// that answer is pinned by
    /// `the_system_resolver_counts_only_no_records_as_absence`.
    #[tokio::test]
    async fn a_missing_txt_record_is_absent_rather_than_an_error() {
        let resolver = StaticDns::new();
        let result = did_from_dns(&resolver, "nonexistent-handle.invalid").await;
        assert!(matches!(result, Ok(None)), "got {result:?}");
    }

    /// **A resolver FAILURE is not "no record".** Treating every error as absent
    /// silently downgrades resolution to the HTTP path, which is the weaker of
    /// the two — and an off-path attacker who can force SERVFAIL or a timeout
    /// gets to choose that downgrade.
    ///
    /// This case needs no network manipulation: a 251-character handle passes
    /// `normalize_handle` (every label is within 63 bytes) but `_atproto.` + 251
    /// exceeds the 255-byte DNS name limit, so name construction fails before a
    /// query is ever issued. FeatherReader drove that through the system
    /// resolver; here the seam reports the same failure, and
    /// `the_system_resolver_queries_the_fqdn` proves `SystemResolver` fails to
    /// construct this very name.
    #[tokio::test]
    async fn a_resolver_failure_is_an_error_rather_than_absence() {
        let label = "a".repeat(60);
        let handle = format!("{label}.{label}.{label}.{label}.com");
        assert!(handle.len() > 240 && handle.len() <= 253);
        assert!(
            identity::normalize_handle(&handle).is_ok(),
            "the handle itself must be valid, or the test proves nothing"
        );

        let resolver = StaticDns::new().failing(&txt_query_name(&handle), "name too long");
        let result = did_from_dns(&resolver, &handle).await;
        assert!(
            result.is_err(),
            "a name-construction failure was reported as 'no record': {result:?}"
        );
    }

    /// The well-known fallback still goes through the SSRF guard, asserted on
    /// the guard's own error rather than merely `is_err()`.
    #[tokio::test]
    async fn the_well_known_fallback_fails_closed_on_an_internal_host() {
        let err = did_from_well_known(&Fetcher::default(), "127.0.0.1")
            .await
            .expect_err("must refuse a loopback handle host");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("forbidden (internal) address"),
            "failed for the wrong reason: {rendered}"
        );
    }

    /// **A well-known 4xx is `NoDid`; a 5xx is not.** A 404 says nothing is
    /// served for that handle (a typo); a 503 is an outage, and calling it
    /// "no such handle" would tell a user to retype a correct handle. The
    /// text is the same either way.
    #[tokio::test]
    async fn a_well_known_4xx_is_no_did_but_403_408_429_and_5xx_are_not() {
        for (status, typed) in [
            (404, true),
            (410, true),
            (400, true),
            // A bot challenge in front of a custom-domain handle, a timeout,
            // a rate limit: not evidence that the handle names no DID.
            (403, false),
            (408, false),
            (429, false),
            (503, false),
            (500, false),
        ] {
            let (addr, _log) = crate::testing::spawn_tls(move |_| {
                let mut r = std::collections::HashMap::new();
                r.insert(
                    "/.well-known/atproto-did".to_string(),
                    vec![crate::testing::TestResponse::json(status, "{}")],
                );
                r
            })
            .await;
            let fetcher = Fetcher::default();
            crate::testing::test_host_override(&fetcher, "pds-e2e.test", addr);
            let err = did_from_well_known(&fetcher, "pds-e2e.test")
                .await
                .expect_err("not a DID");
            let text = format!("{err:#}");
            assert!(
                text.contains(&format!("returned status {status}")),
                "{text}"
            );
            let found = matches!(
                crate::Error::find(&err),
                Some(crate::Error::Resolution(
                    crate::error::ResolutionError::NoDid { .. }
                ))
            );
            assert_eq!(found, typed, "status {status}: {text}");
        }
    }

    /// Reserved TLDs are rejected before any lookup happens, so a `.internal`
    /// handle never becomes a DNS query at all.
    #[tokio::test]
    async fn a_reserved_tld_handle_is_refused_before_any_lookup() {
        let resolver = StaticDns::new();
        let err = resolve(
            &resolver,
            &Fetcher::default(),
            "alice.internal",
            "https://plc.directory",
        )
        .await
        .expect_err("must refuse a reserved TLD");
        assert!(format!("{err:#}").contains("reserved TLD"));
        // The seam makes "before any lookup" observable.
        assert_eq!(resolver.queries(), Vec::<String>::new());
    }

    // ── the decisions `resolve` makes, now that they are reachable ───────────

    const SUBJECT_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    fn doc_claiming(handle: &str) -> serde_json::Value {
        serde_json::json!({
            "id": SUBJECT_DID,
            "alsoKnownAs": [format!("at://{handle}")],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }]
        })
    }

    /// **The document must claim the handle we started from.**
    ///
    /// Dropping the `?` from `verify_handle_claim` inside `resolve` passed the
    /// entire suite: every test of that rule sat on `verify_handle_claim`
    /// itself, and nothing proved the resolution path called it. Without it,
    /// whoever controls a DNS name can point it at any DID at all.
    #[test]
    fn a_handle_the_document_does_not_claim_is_refused() {
        let document = doc_claiming("someone-else.com");
        let err = account_from_handle(&document, "victim.com", SUBJECT_DID)
            .expect_err("a document that claims a different handle must be refused");
        assert!(
            format!("{err:#}").contains("victim.com"),
            "failed for the wrong reason: {err:#}"
        );

        // The matching claim still resolves.
        let ok = account_from_handle(&doc_claiming("alice.com"), "alice.com", SUBJECT_DID)
            .expect("a matching claim must resolve");
        assert_eq!(ok.handle.as_deref(), Some("alice.com"));
        assert_eq!(ok.pds_url, "https://pds.example.com");
    }

    /// **A DID-first handle is reported only when it round-trips back.**
    ///
    /// Relaxing the comparison to accept ANY reverse result passed the suite. A
    /// handle shown beside an account it does not belong to is a lie with a UI
    /// around it.
    #[test]
    fn a_did_first_handle_must_round_trip_to_the_same_did() {
        let document = doc_claiming("alice.com");

        // Came back to us: reported.
        let ok = account_from_did(&document, SUBJECT_DID, Some(SUBJECT_DID)).unwrap();
        assert_eq!(ok.handle.as_deref(), Some("alice.com"));

        // Came back to someone ELSE: withheld.
        let other = account_from_did(
            &document,
            SUBJECT_DID,
            Some("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        assert_eq!(
            other.handle, None,
            "a handle that resolves to a DIFFERENT did was reported as verified"
        );

        // Did not come back at all: withheld.
        let none = account_from_did(&document, SUBJECT_DID, None).unwrap();
        assert_eq!(none.handle, None);

        // Every case still yields the PDS — withholding the handle must not
        // break the login.
        assert_eq!(none.pds_url, "https://pds.example.com");
    }

    /// **DNS wins, and the well-known lookup is not even attempted.**
    ///
    /// Swapping the order passed the whole suite. The rule is not a tie-break:
    /// a real handle was found during the live spike whose
    /// `/.well-known/atproto-did` 404s and which resolves by TXT alone, so an
    /// HTTP-first implementation simply fails on it — and the weaker mechanism
    /// must never be reachable while the stronger one has answered.
    #[tokio::test]
    async fn dns_wins_and_the_well_known_lookup_is_never_called() {
        let called = std::sync::atomic::AtomicUsize::new(0);

        let did = prefer_dns(Some(SUBJECT_DID.to_string()), || async {
            called.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_string())
        })
        .await
        .unwrap();

        assert_eq!(did, SUBJECT_DID, "the DNS answer must win");
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the well-known lookup ran even though DNS had answered"
        );
    }

    /// And it IS called when DNS found nothing — the fallback has to work.
    #[tokio::test]
    async fn the_well_known_lookup_runs_when_dns_has_no_record() {
        let did = prefer_dns(None, || async { Ok(SUBJECT_DID.to_string()) })
            .await
            .unwrap();
        assert_eq!(did, SUBJECT_DID);
    }

    // ── the resolver seam (new in calamus) ───────────────────────────────────

    /// **A record's character-strings are one value.** A TXT record longer than
    /// 255 bytes arrives as several chunks, and they concatenate; reading them as
    /// separate records would split a DID in half (and then report "no did="
    /// record, or a truncated one). The seam hands records over as chunk lists
    /// so `identity::join_txt_chunks` stays the one joiner.
    #[tokio::test]
    async fn a_txt_record_split_across_chunks_resolves_through_the_resolver_seam() {
        let dns = StaticDns::new().with_txt(
            "_atproto.alice.example.com.",
            &[&["did=did:plc:ewvi7nx", "zyoun6zhxrhs64oiz"]],
        );
        let did = did_from_dns(&dns, "alice.example.com").await.unwrap();
        assert_eq!(did.as_deref(), Some(SUBJECT_DID));

        // The same chunks as two RECORDS are not one DID: the first is a
        // truncated `did=` value, the second is not a `did=` record at all.
        let split = StaticDns::new().with_txt(
            "_atproto.alice.example.com.",
            &[&["did=did:plc:ewvi7nx"], &["zyoun6zhxrhs64oiz"]],
        );
        let result = did_from_dns(&split, "alice.example.com").await;
        assert!(
            !matches!(result, Ok(Some(ref d)) if d == SUBJECT_DID),
            "two records were joined into one: {result:?}"
        );
    }

    /// **The trailing dot reaches the resolver.** The FQDN rule is only worth
    /// anything if the name a `DnsResolver` is asked for is the fully-qualified
    /// one, exactly once.
    #[tokio::test]
    async fn the_fqdn_reaches_the_resolver_seam() {
        let dns = StaticDns::new().with_txt(
            "_atproto.alice.example.com.",
            &[&["did=did:plc:ewvi7nxzyoun6zhxrhs64oiz"]],
        );
        let did = did_for_handle(&dns, &Fetcher::default(), "alice.example.com")
            .await
            .unwrap();
        assert_eq!(did, SUBJECT_DID);
        assert_eq!(
            dns.queries(),
            vec!["_atproto.alice.example.com.".to_string()]
        );
    }

    /// **A SERVFAIL does not fall through to the well-known lookup.**
    ///
    /// The well-known server here is real (TLS, reachable through a host
    /// override) and would answer with a DID; the positive control proves it is
    /// reachable when DNS genuinely has no record, so its silence under a
    /// resolver failure means something. An attacker who can induce a resolver
    /// error must not get to choose the weaker mechanism.
    #[tokio::test]
    async fn a_servfail_from_the_resolver_does_not_fall_through_to_well_known() {
        const HOST: &str = "handle-servfail.test";
        crate::testing::register_tls_host(HOST);
        let (addr, log) = crate::testing::spawn_tls(|_| {
            std::collections::HashMap::from([(
                "/.well-known/atproto-did".to_string(),
                vec![crate::testing::TestResponse::json(200, SUBJECT_DID)],
            )])
        })
        .await;
        let fetcher = Fetcher::default();
        crate::testing::test_host_override(&fetcher, HOST, addr);
        let name = txt_query_name(HOST);

        let failing = StaticDns::new().failing(&name, "SERVFAIL");
        let err = did_for_handle(&failing, &fetcher, HOST)
            .await
            .expect_err("a resolver failure must fail the resolution");
        assert!(
            format!("{err:#}").contains("SERVFAIL"),
            "failed for the wrong reason: {err:#}"
        );
        assert_eq!(
            log.lock().unwrap().len(),
            0,
            "the well-known server was asked after a resolver failure"
        );

        // Control: with no record at all, the same server IS asked, and answers.
        let absent = StaticDns::new();
        let did = did_for_handle(&absent, &fetcher, HOST).await.unwrap();
        assert_eq!(did, SUBJECT_DID);
        assert_eq!(log.lock().unwrap().len(), 1);
        assert_eq!(absent.queries(), vec![name]);
    }

    /// Every future the resolution path returns is `Send`, so a caller can spawn
    /// it on a multi-threaded runtime. Compile-time: nothing here is awaited.
    #[test]
    fn the_resolver_seam_and_its_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn generic<D: DnsResolver>(dns: &D, fetcher: &Fetcher) {
            assert_send(&dns.txt("_atproto.alice.example.com."));
            assert_send(&did_from_dns(dns, "alice.example.com"));
            assert_send(&did_for_handle(dns, fetcher, "alice.example.com"));
            assert_send(&resolve(
                dns,
                fetcher,
                "alice.example.com",
                "https://plc.directory",
            ));
        }
        let dns = StaticDns::new();
        let fetcher = Fetcher::default();
        generic(&dns, &fetcher);
        #[cfg(feature = "dns")]
        {
            fn system(dns: &SystemResolver, fetcher: &Fetcher) {
                generic(dns, fetcher);
            }
            let _ = system;
        }
    }

    /// **`SystemResolver` hands hickory the fully-qualified name, and refuses one
    /// that is not.** hickory appends the host's search domains to any name that
    /// is not an FQDN, so the dot `txt_query_name` adds must survive into the
    /// `Name` that is queried, and a caller passing a bare name must get an error
    /// rather than a search-list lookup. Asserted on the `Name` itself, without a
    /// network.
    ///
    /// And the name-too-long case FeatherReader's resolver test relied on: the
    /// 251-byte handle's query name cannot be constructed, so no query is issued
    /// and the lookup is an error, not absence.
    #[cfg(feature = "dns")]
    #[test]
    fn the_system_resolver_queries_the_fqdn() {
        let name = system_query_name(&txt_query_name("alice.example.com")).unwrap();
        assert!(
            name.is_fqdn(),
            "hickory would apply the search list to {name}"
        );
        assert_eq!(name.to_string(), "_atproto.alice.example.com.");

        let err = system_query_name("_atproto.alice.example.com")
            .expect_err("a bare name would be expanded by the search list");
        assert!(
            format!("{err:#}").contains("fully qualified"),
            "failed for the wrong reason: {err:#}"
        );

        let label = "a".repeat(60);
        let handle = format!("{label}.{label}.{label}.{label}.com");
        assert!(
            system_query_name(&txt_query_name(&handle)).is_err(),
            "a name over 255 bytes was constructed"
        );
    }

    /// **Only "no records" is absence.** The one place a hickory error becomes
    /// `Ok(None)`; anything else — SERVFAIL, a timeout, a refused connection — is
    /// an error the caller must not fall through on.
    #[cfg(feature = "dns")]
    #[test]
    fn the_system_resolver_counts_only_no_records_as_absence() {
        use hickory_resolver::net::{NetError, NoRecords};
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::RecordType;

        let query = Query::query(
            system_query_name("_atproto.alice.example.com.").unwrap(),
            RecordType::TXT,
        );
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let absent = NetError::from(NoRecords::new(query.clone(), code));
            assert!(is_no_records(&absent), "{absent} was not absence");
        }
        for failure in [
            NetError::Busy,
            NetError::NoConnections,
            NetError::from(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            NetError::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
        ] {
            assert!(!is_no_records(&failure), "{failure} was treated as absence");
        }
    }
}
