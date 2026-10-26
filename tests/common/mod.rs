//! What every end-to-end suite shares: a client, its stores, and the fake
//! world (`calamus::testing::fake`) it logs in against.
#![allow(dead_code)] // each suite uses a different subset

use calamus::discovery::{discover, AuthorizationServer};
use calamus::keys::SigningKey;
use calamus::login::{Client, CompletedLogin, Deps, StartedLogin};
use calamus::metadata::{ClientMetadata, Jwks};
use calamus::net::Fetcher;
use calamus::session::RefreshContext;
use calamus::store::memory::{MemoryNonces, MemoryPendingLogins, MemorySessions};
use calamus::store::Session;
use calamus::testing::fake::{Fake, FakeConfig, HANDLE};
use calamus::testing::StaticDns;

/// The clock every suite runs on. The fake checks no `iat`, so a fixed one
/// keeps expiries exact.
pub const NOW: i64 = 1_700_000_000;
pub const CLIENT_ID: &str = "https://client-e2e.test/oauth/client-metadata.json";
pub const REDIRECT: &str = "https://client-e2e.test/oauth/callback";
pub const SCOPE: &str = "atproto transition:generic";

/// A confidential client, its stores, and the fake it talks to.
pub struct World {
    pub fake: Fake,
    pub fetcher: Fetcher,
    pub dns: StaticDns,
    pub client: Client,
    pub pending: MemoryPendingLogins,
    pub sessions: MemorySessions,
    pub nonces: MemoryNonces,
}

impl World {
    /// The default world: a did:plc account, nonces always required.
    pub async fn new() -> Self {
        Self::with(|_| {}).await
    }

    /// A world whose fake is configured by `tweak` first.
    pub async fn with(tweak: impl FnOnce(&mut FakeConfig)) -> Self {
        Self::build(SCOPE, tweak).await
    }

    /// A world whose client asks for `scope`.
    pub async fn build(scope: &str, tweak: impl FnOnce(&mut FakeConfig)) -> Self {
        // The fake must know the client's key before the client exists, so
        // the key is minted first and handed to both.
        let key = SigningKey::generate("client-e2e-1");
        let mut config = FakeConfig::confidential(CLIENT_ID, &key);
        tweak(&mut config);
        let fake = Fake::spawn(config).await;
        let metadata = ClientMetadata::confidential(
            url::Url::parse(CLIENT_ID).unwrap(),
            vec![url::Url::parse(REDIRECT).unwrap()],
            scope,
            "calamus e2e",
            None,
            Jwks::Inline(key.jwks_document().unwrap()),
        )
        .unwrap();
        let client = Client::new(metadata, Some(key), fake.plc_url()).unwrap();
        Self {
            fetcher: fake.fetcher(),
            dns: fake.dns(),
            fake,
            client,
            pending: MemoryPendingLogins::new(),
            sessions: MemorySessions::new(),
            nonces: MemoryNonces::new(),
        }
    }

    pub fn deps(&self) -> Deps<'_, StaticDns, MemoryPendingLogins, MemorySessions, MemoryNonces> {
        Deps {
            fetcher: &self.fetcher,
            dns: &self.dns,
            pending: &self.pending,
            sessions: &self.sessions,
            nonces: &self.nonces,
        }
    }

    pub async fn start(&self, subject: &str) -> anyhow::Result<StartedLogin> {
        self.client.start(&self.deps(), subject, NOW).await
    }

    /// Start, approve, and complete a login for `alice-e2e.test`.
    pub async fn login(&self) -> CompletedLogin {
        let started = self.start(HANDLE).await.expect("the login starts");
        let params = self
            .fake
            .approve(&started.authorize_url)
            .expect("the fake approves");
        self.client
            .complete(&self.deps(), &params, Some(&started.binding_token), NOW)
            .await
            .expect("the login completes")
    }

    /// Discover the session's authorization server, expecting its issuer:
    /// what a caller does before refreshing or signing out.
    pub async fn discover_for(&self, session: &Session) -> anyhow::Result<AuthorizationServer> {
        discover(
            &self.fetcher,
            &session.aud,
            self.client.auth_method().as_str(),
            Some(&session.issuer),
        )
        .await
    }

    /// A refresh context for `server`.
    pub fn refresh_context<'a>(&'a self, server: &'a AuthorizationServer) -> RefreshContext<'a> {
        RefreshContext {
            token_endpoint: &server.token_endpoint,
            client_id: self.client.client_id(),
            auth_method: self.client.auth_method(),
            client_key: self.client.key(),
            revocation_endpoint: server.revocation_endpoint.as_deref(),
            issuer: &server.issuer,
        }
    }
}

/// The session's DPoP key thumbprint.
pub fn session_jkt(session: &Session) -> String {
    SigningKey::public_thumbprint_of(&session.dpop_key_jwk).unwrap()
}
