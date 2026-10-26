#!/usr/bin/env bash
# The gate every change passes, locally and in CI (the same steps as FeatherReader's).
set -euo pipefail
cd "$(dirname "$0")/.."
# Never share a target dir with another checkout: a shared one once ran another
# worktree's stale test binary as "this" checkout's tests.
target=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
case "$target" in "$PWD"/target) ;; *) echo "target dir is $target, not $PWD/target: unset CARGO_TARGET_DIR"; exit 1;; esac
cargo fmt --all --check
cargo build --all-targets --all-features --locked
cargo test --all-features --locked
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
# And with default features: a link to a feature-gated item breaks only there.
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
# The test seams are absent from a build without `test-util`.
#
# `calamus::testing` hands out per-Fetcher host overrides that skip the SSRF
# guard for a named host, and a test CA the Fetcher then trusts. They must not
# exist unless a caller turns `test-util` on (from [dev-dependencies] only), and
# a default build must not be able to reach them. Three checks, each of which
# fails if someone wires a seam into the ordinary build:
#
# 1. A probe crate depending on calamus WITHOUT the feature calls
#    `calamus::testing::test_host_override`. It must fail to compile, and with
#    the one error that says `testing` does not exist; any other failure (a typo,
#    a moved type) is not evidence and fails this step. The same probe WITH the
#    feature must compile: the positive control that the probe reaches for the
#    real path, so the negative result means something. Ungating the `testing`
#    module, or re-exporting the override from anywhere public under the same
#    path, turns the negative compile green and fails here.
# 2. Clippy over the library with no features and -D warnings. The override
#    table, its lookup and the CA trust are `cfg(any(test, feature = "test-util"))`
#    and only reachable from `testing`; ungating any of them without a public
#    entry point leaves it dead in this build, which `dead_code` refuses.
# 3. rcgen (the test PKI) is not in the normal dependency graph without the
#    feature, so no build without it can mint or trust a test certificate.
probe=target/release-graph-probe
rm -rf "$probe" && mkdir -p "$probe/src"
cat > "$probe/Cargo.toml" <<'TOML'
[package]
name = "release-graph-probe"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
calamus = { path = "../.." }

[features]
test-util = ["calamus/test-util"]
TOML
cat > "$probe/src/main.rs" <<'RUST'
fn main() {
    let fetcher = calamus::net::Fetcher::default();
    calamus::testing::test_host_override(&fetcher, "probe.test", ([127, 0, 0, 1], 1).into());
}
RUST
cp Cargo.lock "$probe/Cargo.lock"
probe_check() { cargo check --offline --quiet --manifest-path "$probe/Cargo.toml" --target-dir "$probe/target" "$@" 2>&1; }
if out=$(probe_check); then
  echo "release graph: calamus::testing compiled WITHOUT test-util"; exit 1
fi
if ! grep -q 'could not find `testing` in `calamus`' <<<"$out"; then
  echo "$out"; echo "release graph: the probe failed for a reason other than testing being absent"; exit 1
fi
if ! out=$(probe_check --features test-util); then
  echo "$out"; echo "release graph: the probe does not compile even WITH test-util, so its negative result proves nothing"; exit 1
fi
cargo clippy --lib --locked -- -D warnings
if cargo tree -e normal --locked --prefix none | grep -E '^rcgen '; then
  echo "release graph: the test PKI (rcgen) is in the graph without test-util"; exit 1
fi
cargo deny check bans licenses sources
cargo audit -D warnings
echo "ci: all green"
