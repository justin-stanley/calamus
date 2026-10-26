//! **Live discovery against a real atproto PDS.**
//!
//! `#[ignore]` — it talks to the network. Run with:
//!
//! ```text
//! cargo test --test live_pds -- --ignored --nocapture
//! ```
//!
//! Closes part of "never validated against a live PDS": handle resolution,
//! the protected-resource document, AS metadata, and BOTH mix-up defences
//! (issuer self-description and endpoint co-location) run against a server
//! that pushes back. Read-only and unauthenticated — no account, no consent,
//! no tokens, no side effects on the PDS.
//!
//! What it does NOT cover: PAR, `private_key_jwt`, the code exchange and
//! revocation. Those need our client metadata to be fetchable by the PDS at
//! the `client_id` URL, which means the cutover itself.
//!
//! Ported from FeatherReader `src/oauth/discovery.rs` (`mod live_pds`), which
//! built its HTTP client with `feed::build_client`; this uses calamus's own
//! [`Fetcher`] with the default policy, and the system resolver.
#![cfg(feature = "dns")]

use calamus::discovery::discover;
use calamus::net::Fetcher;
use calamus::resolve::{resolve, SystemResolver};

const SUBJECT: &str = "justin-stanley.com";
const PLC: &str = "https://plc.directory";

#[tokio::test]
#[ignore]
async fn discovery_round_trips_against_a_live_pds() -> anyhow::Result<()> {
    let http = Fetcher::default();
    let resolver = SystemResolver::from_system_config()?;

    let account = resolve(&resolver, &http, SUBJECT, PLC).await?;
    println!("resolved {SUBJECT}");
    println!("  did: {}", account.did);
    println!("  handle verified: {:?}", account.handle);
    println!("  pds: {}", account.pds_url);

    let server = discover(&http, &account.pds_url, "private_key_jwt", None).await?;
    println!("discovery:");
    println!("  issuer:        {}", server.issuer);
    println!("  par:           {}", server.par_endpoint);
    println!("  authorization: {}", server.authorization_endpoint);
    println!("  token:         {}", server.token_endpoint);
    println!(
        "  revocation:    {}",
        server.revocation_endpoint.as_deref().unwrap_or("(absent)")
    );

    // A real server must satisfy the mix-up defences, not just parse.
    assert!(
        server.issuer.starts_with("https://"),
        "issuer must be https"
    );
    assert!(
        !server.par_endpoint.is_empty() && !server.token_endpoint.is_empty(),
        "a PDS must advertise PAR and token endpoints"
    );
    // Re-running with the issuer we just learned must be accepted — this is
    // the check the refresh and revoke paths make on every call.
    let again = discover(
        &http,
        &account.pds_url,
        "private_key_jwt",
        Some(&server.issuer),
    )
    .await?;
    assert_eq!(again.issuer, server.issuer);

    // And an impostor issuer must be REFUSED. This is the mix-up defence
    // running against real metadata rather than a fixture.
    let bad = discover(
        &http,
        &account.pds_url,
        "private_key_jwt",
        Some("https://evil.example"),
    )
    .await;
    // **Assert WHY it was refused, not merely that it was.** `is_err()` alone
    // is satisfied by a transient network failure on this third call, so it
    // would keep passing if the mix-up check stopped firing and something
    // else errored instead — the defence would silently stop being tested
    // while the test stayed green.
    let err = format!(
        "{:#}",
        bad.expect_err("a mismatched issuer must be refused")
    );
    assert!(
        err.contains("different authorization server")
            && err.contains("refusing to send credentials"),
        "refused, but not BY the mix-up defence — this test would not notice \
         if that check stopped firing: {err}"
    );
    println!("  mix-up defence: refused a mismatched issuer, by `same_issuer`");

    // Revocation support is what decides whether logout can tell the PDS.
    match server.revocation_endpoint {
        Some(ref r) => println!("\n  => this PDS SUPPORTS RFC 7009 revocation at {r}"),
        None => println!("\n  => this PDS advertises NO revocation endpoint"),
    }
    Ok(())
}
