#!/usr/bin/env bash
# Part of scripts/ci.sh, runnable on its own.
set -euo pipefail
cd "$(dirname "$0")/.."
# The test seams are absent from a build without `test-util`.
#
# `calamus::testing` hands out per-Fetcher host overrides that skip the SSRF
# guard for a named host, and a test CA the Fetcher then trusts. They must not
# exist unless a caller turns `test-util` on (from [dev-dependencies] only), and
# a default build must not be able to reach them. Five checks, each of which
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

# 4. A second probe tries the override as a Fetcher method, the shape an ungated
#    seam would most naturally take, and must fail to compile with "no method".
cat > "$probe/src/main.rs" <<'RUST'
fn main() {
    let fetcher = calamus::net::Fetcher::default();
    fetcher.add_host_override("probe.test", ([127, 0, 0, 1], 1).into());
}
RUST
if out=$(probe_check); then
  echo "release graph: Fetcher::add_host_override exists WITHOUT test-util"; exit 1
fi
if ! grep -q 'no method named `add_host_override`' <<<"$out"; then
  echo "$out"; echo "release graph: the method probe failed for a reason other than the method being absent"; exit 1
fi
# 5. The default-feature public API of `Fetcher` is exactly this list, read from
#    the rustdoc of a build without features. An override entry point under any
#    name, or anything else new, fails here until it is added deliberately.
#    rustdoc never deletes stale pages, so the crate's docs are cleared first;
#    and with them gone, `testing` must not be documented at all.
rm -rf target/doc/calamus
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked --quiet
if [ -e target/doc/calamus/testing ]; then
  echo "release graph: calamus::testing is documented in a build without test-util"; exit 1
fi
methods=$(python3 - <<'PY'
import re
s = open("target/doc/calamus/net/struct.Fetcher.html").read()
i, j = s.index('id="implementations"'), s.index('id="trait-implementations"')
print(" ".join(sorted(set(re.findall(r'id="method\.([A-Za-z0-9_]+)"', s[i:j])))))
PY
)
expected="assert_public_target get get_no_redirect get_without_hop_policy new policy post_form post_json read_capped"
if [ "$methods" != "$expected" ]; then
  echo "release graph: Fetcher's public methods without test-util are [$methods], expected [$expected]"; exit 1
fi
echo "release graph: test seams absent"
