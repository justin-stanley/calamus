# Contributing to calamus

Thanks for looking. calamus is a small, security-sensitive library with one maintainer, so the
bar for a change is high but plain: **it's tested, it passes the gate, and it says why.**

## Before you start

- **Bugs**: open an issue with what you expected, what happened, and the smallest reproduction you
  have. Ideally that's a test against `calamus::testing::fake`.
- **Security issues**: don't open an issue. See [SECURITY.md](SECURITY.md).
- **Features and API changes**: open an issue first, so we can agree on the shape before you write
  it. The API is pre-1.0 and can change, but every change has a cost for callers.

## The gate

Every change passes `scripts/ci.sh`, which is exactly what CI runs:

```sh
scripts/ci.sh   # ends with "ci: all green"
```

It covers:
- `cargo fmt`;
- build, tests and clippy (`-D warnings`), with every feature and with none;
- rustdoc with `-D warnings`;
- a check that every end-to-end suite still has tests;
- the release-graph check;
- `cargo deny` and `cargo audit`.

If it's green locally, it's green in CI. Don't point `CARGO_TARGET_DIR` at a directory another
checkout uses; the script refuses to run that way, because a shared target dir once ran another
checkout's stale test binary.

## What a good pull request has

- **A test that fails without the change.** For a bug fix, check this by reverting the fix where
  it's *called*, not only in a helper. A test that still passes with the bug put back proves
  nothing.
- **Changes to security-relevant code** (`net`, `dpop`, `client_auth`, `keys`, `jwt`, `token`,
  `revoke`) also get mutation testing on the lines they touch:

  ```sh
  git diff origin/main > /tmp/pr.diff && cargo mutants --in-diff /tmp/pr.diff --all-features
  ```

  List any surviving mutants in the pull request, with a reason why each is acceptable.
- **A CHANGELOG entry** under *Unreleased*: what changed, the mechanism, and, for a defect, how it
  was established. Breaking changes and MSRV bumps also go under *Upgrade notes*.
- **Docs** for any public item: what it does, what it refuses, and why. Doc comments are
  checked with `-D warnings`.
- **One concern per pull request.** It's squash-merged, so its title becomes the commit
  subject on `main`.

Pull requests are reviewed until a full pass finds nothing above a nit. Expect more than one round
on anything touching the protocol or the fetcher: later passes regularly find problems in earlier
fixes.

## Licensing of contributions

calamus is [AGPL-3.0-only](LICENSE). By submitting a contribution you agree it's licensed the same
way. There's no CLA.

## Releases

Releases follow the same discipline as [FeatherReader](https://github.com/justin-stanley/feather-reader):

1. **Release pull request**: the version in `Cargo.toml` and `Cargo.lock`; *Unreleased* in the
   changelog becomes `## X.Y.Z — date` with a summary; and the absolute
   `raw.githubusercontent.com/.../main/` and `blob/main/` URLs in `README.md` and `src/lib.rs`
   are pinned to the tag `vX.Y.Z`, so the published README and docs keep pointing at that
   release's files.
2. **Release candidate**: an annotated tag `vX.Y.Z-rc.N`. Release candidates are never published to
   crates.io (the release workflow refuses any tag containing `-`) and get no GitHub release.
3. **Soak in FeatherReader.** calamus has no staging of its own, so its reference consumer is its
   staging. FeatherReader builds a release candidate on the calamus candidate and runs its own
   staging soak of at least 24 hours: a real sign-in, a token refresh, a sign-out, and a rollback.
4. **Live PDS test**: `cargo test --test live_pds -- --ignored`, with the result recorded in the
   release pull request.
5. **Final tag** `vX.Y.Z` on the candidate's commit. The release workflow then:
   - waits for the maintainer's approval in the `crates-io` environment;
   - packages and verifies the crate in a job with no publish credential, then publishes the
     byte-identical crate with crates.io Trusted Publishing (no stored token; the very first
     publish, 0.1.0, uses a one-time token, because crates.io can't create a crate through
     Trusted Publishing);
   - attests the build provenance of the `.crate` file;
   - creates the GitHub release from the changelog section.

You can verify a published crate came from this repository's release workflow:

```sh
gh attestation verify calamus-X.Y.Z.crate --repo justin-stanley/calamus
```
