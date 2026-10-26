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
# And with no optional features at all (no `dns`, no `revoke`, no `test-util`):
# the core revocation request and the refresh path that needs it are always
# built, and an item used only by a gated feature must be gated with it.
cargo test --no-default-features --locked
cargo clippy --all-targets --no-default-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
# And with default features: a link to a feature-gated item breaks only there.
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
scripts/release-graph-check.sh
cargo deny check bans licenses sources
cargo audit -D warnings
echo "ci: all green"
