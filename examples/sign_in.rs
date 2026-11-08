//! A complete atproto OAuth sign-in, refresh and sign-out, run offline.
//!
//! ```sh
//! cargo run --example sign_in --features test-util,revoke
//! ```
//!
//! Everything a real login does happens here: the handle is resolved to a DID
//! and the DID to its PDS, the PDS's authorization server is discovered, the
//! request is pushed (PAR) with PKCE and a DPoP proof, the callback is
//! completed and its `sub` checked against the DID, the session is refreshed
//! once its access token is stale, and the tokens are revoked on sign-out. The
//! only difference from production is where the requests go: to
//! `calamus::testing::fake`, a loopback authorization server, PDS, PLC
//! directory and DNS that check every proof the real ones do. Nothing touches
//! the network.
//!
//! In a real app, `fake.fetcher()` becomes `Fetcher::new(FetchPolicy::default())`,
//! `fake.dns()` becomes `SystemResolver::from_system_config()`, the memory
//! stores become your database, and `fake.approve(...)` is the user's browser
//! visiting `authorize_url` and coming back to your callback.

use anyhow::Result;
use calamus::discovery::discover;
use calamus::keys::SigningKey;
use calamus::login::{Client, Deps};
use calamus::metadata::{ClientMetadata, Jwks};
use calamus::revoke::{sign_out, Revocation, RevokeContext};
use calamus::session::{valid_session, RefreshContext};
use calamus::store::memory::{MemoryNonces, MemoryPendingLogins, MemorySessions};
use calamus::testing::fake::{Fake, FakeConfig, HANDLE};
use url::Url;

const CLIENT_ID: &str = "https://reader.example/oauth/client-metadata.json";
const REDIRECT: &str = "https://reader.example/oauth/callback";

#[tokio::main]
async fn main() -> Result<()> {
    // A confidential client signs its token requests with its own ES256 key and
    // publishes the public half. Generate it once and keep it: the client's
    // identity is its client_id plus this key.
    let key = SigningKey::generate("reader-1");
    let metadata = ClientMetadata::confidential(
        Url::parse(CLIENT_ID)?,
        vec![Url::parse(REDIRECT)?],
        "atproto transition:generic",
        "Example Reader",
        None,
        Jwks::Inline(key.jwks_document()?),
    )?;

    // The fake world: it knows the client's key, as a real authorization server
    // learns it from the client metadata document.
    let fake = Fake::spawn(FakeConfig::confidential(CLIENT_ID, &key)).await;
    let client = Client::new(metadata, Some(key), fake.plc_url())?;

    let fetcher = fake.fetcher();
    let dns = fake.dns();
    let (pending, sessions, nonces) = (
        MemoryPendingLogins::new(),
        MemorySessions::new(),
        MemoryNonces::new(),
    );
    let deps = Deps {
        fetcher: &fetcher,
        dns: &dns,
        pending: &pending,
        sessions: &sessions,
        nonces: &nonces,
    };
    let now = unix_now();

    // 1. The user types their handle. Send the browser to `authorize_url`, and
    //    set `binding_token` as a cookie: the callback must present it.
    let started = client.start(&deps, HANDLE, now).await?;
    println!("1. pushed the authorization request for {HANDLE}");
    println!("   send the browser to: {}", started.authorize_url);

    // 2. The user approves at their server, which redirects back to the callback.
    let callback = fake.approve(&started.authorize_url)?;

    // 3. The callback: exchange the code, check the account, store the session.
    let login = client
        .complete(&deps, &callback, Some(&started.binding_token), now)
        .await?;
    println!("2. signed in as {} ({:?})", login.did, login.handle);

    // 4. Later, before calling the PDS: get a valid session, refreshing it if
    //    the access token is stale. Here, an hour and a bit later.
    let server = discover(
        &fetcher,
        &login.session.aud,
        client.auth_method().as_str(),
        Some(&login.session.issuer),
    )
    .await?;
    let later = now + 4_000;
    let fresh = valid_session(
        &sessions,
        &fetcher,
        &nonces,
        client.locks(),
        &login.did,
        &RefreshContext::new(&server, &client),
        later,
    )
    .await?;
    println!(
        "3. refreshed: new access token, valid until {:?}",
        fresh.expires_at
    );

    // 5. Sign out: revoke the tokens at the authorization server, then forget them.
    let outcome = sign_out(
        &sessions,
        &fetcher,
        &nonces,
        &RevokeContext::new(&server, &client),
        &login.did,
        later,
    )
    .await;
    println!("4. signed out: {outcome:?}");
    assert_eq!(outcome, Revocation::Revoked);
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
