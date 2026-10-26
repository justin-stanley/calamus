# calamus

A Rust atproto OAuth client library: handle and DID resolution, authorization-server
discovery, PAR + PKCE + DPoP, `private_key_jwt` client authentication, token exchange with
`sub` verification, refresh and revocation, and DPoP-bound XRPC calls. Behind all of it is
an SSRF-guarded HTTP fetcher, because every one of those steps fetches a URL that someone
else chose.

It's being extracted from [FeatherReader](https://github.com/justin-stanley/feather-reader)'s
`src/oauth/` and `src/net.rs`, where it already runs in production (it replaced FeatherReader's
Node OAuth sidecar in 0.5.0; `private_key_jwt` and revocation were proven there for #262), so
that **Rubrica** (the wiki software) can sign editors in with their atproto
identity without a second implementation to patch.

The name: the calamus is the hollow shaft of a feather, the part cut into a quill pen, and
the Latin word for the reed pen scribes wrote rubrics with. It's the piece FeatherReader and
Rubrica share.

Status: the code is here. Stages 1–10 of
[`design/EXTRACTION-PLAN.md`](design/EXTRACTION-PLAN.md) are built and gated in this repo
(550 tests passing with `--all-features`, 463 with `--no-default-features`, doctests
included); FeatherReader has not adopted it yet and the crate is not published. What
remains is in the plan's status section. The gate is `scripts/ci.sh`, which ends in
`ci: all green`.

## Running the tests

```sh
scripts/ci.sh                         # the gate: fmt, build, tests, clippy, docs, deny, audit
cargo test --all-features             # every unit and end-to-end test
cargo test --all-features --test 'e2e_*'   # just the end-to-end suites
cargo test --test live_pds -- --ignored    # the one test that talks to a real PDS
```

The **end-to-end suites** (`tests/e2e_*.rs`) drive the real `Client::start` and
`Client::complete`, refresh, sign-out and XRPC calls against
`calamus::testing::fake`: one loopback TLS server answering as the account's handle
host, a PLC directory, the PDS and its authorization server (plus two others for the
mix-up cases), with a static DNS resolver. The fake verifies what a real server does
(DPoP signatures, `htm`/`htu`, single-use `jti`, nonces, `ath`, PKCE S256, the
grant's key binding, `private_key_jwt` assertions, single-use rotating refresh
tokens) and each of those checks has a negative-control test proving it refuses a bad
request. They need the `test-util` feature (and `revoke` / `xrpc` for those suites),
which `--all-features` turns on; without it Cargo skips them. **None of them touches
the network**: every host is a host override onto loopback, and the client still runs
its SSRF guard and validates the test CA's certificate for real.

| suite | covers |
|---|---|
| `e2e_login` | handle (TXT and well-known) and DID logins, did:web, the `sub` check, nonce retries, wrong `iss`, foreign browser, repointed PDS, replayed callback, private-address PDS, redirected DID document, and the fake's PKCE / DPoP-key / signature / assertion-`aud` controls |
| `e2e_identity_only` | sign-in-only clients (`atproto` scope, inline JWKS, `store::Discard`) |
| `e2e_refresh` | rotation, refresh-token reuse, 5xx, a moved issuer, concurrent refreshes |
| `e2e_revoke` | sign-out with the session's DPoP key, no revocation endpoint, a hanging server |
| `e2e_xrpc` | the resource server's nonce challenge, and the fake's `ath` control |
| `e2e_proof_replay` | no DPoP proof is ever sent twice, and the fake's replay control |

A crate that uses calamus can run its own flows against the same fake: enable
`test-util` in `[dev-dependencies]` only (`scripts/release-graph-check.sh` proves it is
absent from a default build), and see `calamus::testing::fake::Fake`.
