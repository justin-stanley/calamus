<!-- Badges for crates.io and docs.rs are added with the first published release (design/OPEN-SOURCE.md §6). -->
[![CI](https://github.com/justin-stanley/calamus/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/justin-stanley/calamus/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/justin-stanley/calamus/badge)](https://scorecard.dev/viewer/?uri=github.com/justin-stanley/calamus)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)
[![MSRV 1.94](https://img.shields.io/badge/MSRV-1.94-orange.svg)](#minimum-supported-rust-version)

# calamus

**An [atproto](https://atproto.com) OAuth client for Rust**: sign people in with their atproto
identity (Bluesky, or any PDS) from a server-side app.

calamus does the whole client side of the [atproto OAuth profile](https://atproto.com/specs/oauth):

- **Identity resolution**: handle → DID by DNS TXT or `/.well-known/atproto-did`, verified back
  the other way; DID → PDS for `did:plc` and `did:web`.
- **Authorization-server discovery**, with the issuer checks that stop one server from claiming
  another's accounts.
- **PAR, PKCE (S256) and DPoP**, server nonces included.
- **`private_key_jwt`** client authentication for confidential clients. The localhost development
  client is supported too.
- **The callback**: `state`, RFC 9207 `iss`, a browser-binding check against login CSRF, the code
  exchange, and the token response's `sub` checked against the DID the login started from.
- **Sessions**: refresh with single-use rotating refresh tokens, serialized per account;
  **revocation** (RFC 7009) on sign-out.
- **XRPC calls** to the user's PDS with DPoP-bound tokens.

Every one of those steps fetches a URL that someone else chose, so every request goes through an
**SSRF-guarded HTTP client**. It refuses private, loopback, link-local and other non-public
addresses after DNS resolution and on every redirect hop, caps bodies and timeouts, and never
forwards credentials across origins.

calamus runs in production in [FeatherReader](https://github.com/justin-stanley/feather-reader),
an atproto-native feed reader, where it was written and from which it was extracted.

> **Status: pre-release.** The code is complete and tested, but calamus is not on crates.io yet.
> It will be published as 0.1.0 once FeatherReader has switched to it
> ([the plan](design/OPEN-SOURCE.md)). Until then, depend on it by git tag.

## Quick start

```toml
[dependencies]
calamus = { git = "https://github.com/justin-stanley/calamus" }
```

```rust,ignore
use calamus::login::{Client, Deps};

// Once, at startup: the client's metadata, key, fetcher, resolver and stores.
let client = Client::new(metadata, Some(key), "https://plc.directory")?;

// The user submits their handle. Send the browser to `authorize_url`, and set
// `binding_token` as a cookie.
let started = client.start(&deps, "alice.bsky.social", now).await?;

// Your callback: the query parameters, and the cookie the browser presents.
let login = client.complete(&deps, &callback, Some(cookie), now).await?;
println!("signed in as {}", login.did);
```

The full version, with every type and import, is the crate documentation's first example. To see a
complete sign-in, refresh and sign-out run, try the example. It runs offline, against a bundled
fake authorization server and PDS that check every proof a real one does:

```sh
cargo run --example sign_in --features test-util,revoke
```

### Wiring it into a web app

If your pages send `Content-Security-Policy: form-action 'self'`, **don't answer the sign-in
form's POST with a redirect to the PDS.** Browsers apply `form-action` to where a form submission
ends up, redirects included. Chrome and Safari refuse the redirect silently, so the sign-in button
appears to do nothing. Answer with a small page that continues with
`<meta http-equiv="refresh" content="0; url=…">` and a link. FeatherReader
[hit this and fixed it that way](https://github.com/justin-stanley/feather-reader/pull/356).

## Features

| feature | default | adds |
|---|---|---|
| `dns` | yes | `resolve::SystemResolver`: handle lookup by DNS TXT through the system's resolver |
| `revoke` | no | `revoke::sign_out`: revoke a session's tokens, then delete it, safely against a concurrent refresh |
| `xrpc` | no | `xrpc::Repo`: DPoP-bound XRPC calls to the user's PDS |
| `test-util` | no | `calamus::testing`: the fake authorization server, PDS, PLC directory and DNS. **Use it only in `[dev-dependencies]`**, because it can bypass the SSRF guard for named hosts |

Storage is yours: implement the `store` traits (`SessionStore`, `PendingLoginStore`, `NonceStore`)
on your database. In-memory versions are included for tests and single-process apps.

## How it's tested

About 550 tests run with every feature on, and about 460 with none. The **end-to-end suites**
(`tests/e2e_*.rs`) drive the real `Client::start` and `Client::complete`, refresh, sign-out and
XRPC calls against `calamus::testing::fake`. That's one loopback TLS server answering as the
account's handle host, a PLC directory, the PDS and its authorization server (plus two others for
the mix-up cases), with a static DNS resolver.

The fake verifies what a real server does:
- DPoP signatures, `htm`/`htu`, single-use `jti`, nonces and `ath`;
- PKCE S256 and the grant's key binding;
- `private_key_jwt` assertions;
- single-use rotating refresh tokens.

Each of those checks has a negative-control test proving it refuses a bad request. **None of them
touches the network**: every host is a host override onto loopback, and the client still runs its
SSRF guard and validates the test CA's certificate for real.

| suite | covers |
|---|---|
| `e2e_login` | handle (TXT and well-known) and DID logins, did:web, the `sub` check, nonce retries, wrong `iss`, foreign browser, repointed PDS, replayed callback, private-address PDS, redirected DID document, and the fake's PKCE / DPoP-key / signature / assertion-`aud` controls |
| `e2e_identity_only` | sign-in-only clients (`atproto` scope, inline JWKS, `store::Discard`) |
| `e2e_refresh` | rotation, refresh-token reuse, 5xx, a moved issuer, concurrent refreshes |
| `e2e_revoke` | sign-out with the session's DPoP key, no revocation endpoint, a hanging server |
| `e2e_xrpc` | the resource server's nonce challenge, and the fake's `ath` control |
| `e2e_proof_replay` | no DPoP proof is ever sent twice, and the fake's replay control |
| `e2e_errors` | the typed `calamus::Error` behind every decision a caller matches on |

Your app can run its own flows against the same fake: enable `test-util` in
`[dev-dependencies]` only and see `calamus::testing::fake::Fake`.
`scripts/release-graph-check.sh` proves the test seams are absent from a default build.

```sh
scripts/ci.sh                             # the whole gate, exactly as CI runs it
cargo test --all-features                 # every unit and end-to-end test
cargo test --test live_pds -- --ignored   # the one test that talks to a real PDS
```

## Minimum supported Rust version

1.94. Raising it is a minor-version change and is called out in the [changelog](CHANGELOG.md).

## Security

calamus is security-sensitive by nature. Please **don't** report vulnerabilities in public
issues. Use [private vulnerability reporting](https://github.com/justin-stanley/calamus/security/advisories/new)
instead; [SECURITY.md](SECURITY.md) has the details and what to expect.

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) explains the gate every
change passes (`scripts/ci.sh`) and how releases work. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## License

[AGPL-3.0-only](LICENSE). That includes code that links calamus into a network service. If that
doesn't fit your project, open an issue to talk about it.

## The name

The calamus is the hollow shaft of a feather: the part cut into a quill pen, and the Latin word for
the reed pen scribes wrote rubrics with. It's the piece FeatherReader and its siblings share.
