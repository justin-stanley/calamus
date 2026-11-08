# Changelog

Engineering detail, newest first. Work that has landed on `main` but is not yet released appears
under **Unreleased**.

Each entry says what changed, the mechanism, and — where a defect is involved — how it was
established rather than assumed. Breaking changes and MSRV bumps are listed under **Upgrade
notes**.

calamus follows [Semantic Versioning](https://semver.org). Before 1.0, a breaking change bumps the
minor version. Versions are git tags (`vX.Y.Z`); a release candidate (`vX.Y.Z-rc.N`) is tagged
first and is never published to crates.io (see [CONTRIBUTING.md](CONTRIBUTING.md#releases)).

---

## Unreleased

The first public release will be **0.1.0**: FeatherReader's atproto OAuth client and SSRF-guarded
fetcher, extracted into a library. Not yet published.

### Added

- **The client**, extracted from FeatherReader's `src/oauth/` and `src/net.rs`, which have run in
  production since FeatherReader 0.3.0 (2026-09-13). It does identity resolution (handle and DID,
  `did:plc` and `did:web`), authorization-server discovery with issuer checks, PAR + PKCE + DPoP,
  `private_key_jwt`, the callback with RFC 9207 `iss` and a browser-binding check, the `sub` check
  on the token response, refresh with rotating refresh tokens, revocation (RFC 7009), and
  DPoP-bound XRPC calls. Built test-first in ten stages,
  then reviewed repeatedly until a full
  pass found nothing above Low.
- **Storage traits** (`store::SessionStore`, `PendingLoginStore`, `NonceStore`), with in-memory
  versions and `store::Discard` for sign-in-only clients.
- **A typed `calamus::Error`** for every decision a caller matches on, with the messages pinned by
  `tests/e2e_errors.rs`.
- **`calamus::testing::fake`** (feature `test-util`): a stateful fake authorization server, PDS,
  PLC directory and DNS that verify what real ones do. Every check has a negative-control test.
  `scripts/release-graph-check.sh` proves the seams are absent from a default build.
- **`examples/sign_in.rs`**: a complete sign-in, refresh and sign-out, offline.

### Changed

- TLS uses rustls with the **ring** provider (`reqwest`'s `rustls-no-provider` + `rustls/ring`);
  `aws-lc-sys` and CMake are gone from the graph. ring still compiles its own C and assembly, so
  a C compiler is needed, CMake is not. `calamus::net::install_crypto_provider` installs the
  provider idempotently; the client calls it. `scripts/ci.sh` fails if `aws-lc-sys` or
  `aws-lc-rs` returns.

### Stricter than FeatherReader

Found while extracting, and fixed here first. FeatherReader takes these fixes when it adopts
calamus:

- **Redirects**: credentials dropped on a cross-origin hop stay dropped. An `a → b → a` chain no
  longer re-attaches them.
- **Refresh and revocation** refuse a session issued by another authorization server. Sign-out
  leaves such a row in place and reports it (`Revocation::LeftInPlace`), where FeatherReader's
  fixed-endpoint sign-out sent and deleted it. A failed delete is also `LeftInPlace`.
- **`invalid_grant`** deletes only the session version the refresh started from, and refresh
  tokens from a successful refresh that could not be stored are revoked rather than dropped.
- **Times**: proofs and assertions carry the time they are minted (`iat`/`exp`), not the time the
  call began, and expiry arithmetic saturates.
- **Refresh locks** drop idle accounts instead of growing without bound.
- **Smaller checks**:
  - a pending login is bound to its `client_id`;
  - a missing DID is a typed `NoDid`;
  - NSIDs are validated;
  - `Client::new` checks that an inline JWKS publishes the signing key;
  - `Debug` output redacts codes, tokens and keys.

### Upgrade notes

- A consumer that installed aws-lc-rs as the process default keeps it: calamus installs ring only
  when no provider is set.
