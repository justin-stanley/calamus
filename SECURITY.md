# Security policy

calamus handles sign-in tokens and fetches URLs chosen by other people, so security reports get
priority over everything else.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub's
[private vulnerability reporting](https://github.com/justin-stanley/calamus/security/advisories/new).
Include what you found, how to reproduce it, and what an attacker gains. A failing test or a
proof of concept against `calamus::testing::fake` is ideal, but not required.

What to expect:

| | |
|---|---|
| Acknowledgement | within 3 days |
| First assessment (accepted or not, and a severity) | within 7 days |
| Fix released | as fast as the severity warrants; critical issues are worked on immediately |
| Credit | in the advisory and the changelog, unless you'd rather not be named |

calamus has one maintainer, so these are targets, not guarantees. You'll be kept informed either
way.

## What happens next

A confirmed vulnerability gets:
1. a fix with a test that fails without it;
2. a patch release on the latest minor version;
3. a GitHub security advisory and a [RustSec](https://rustsec.org) advisory, so `cargo audit`
   warns everyone using an affected version;
4. the affected versions **yanked** from crates.io once a fixed version is available.

## Supported versions

The latest minor release gets security fixes. calamus is pre-1.0 and not yet on crates.io (see
[the README](README.md)); until the first release, fixes land on `main`.

## Scope

In scope: anything in this crate. That includes the SSRF guard (`calamus::net`), token and key
handling, and the protocol checks (issuer, `state`, `sub`, PKCE, DPoP, browser binding).

Out of scope:
- Vulnerabilities in dependencies, unless calamus uses them unsafely. Report those upstream;
  `cargo audit` runs on `main` daily.
- Anything that needs the `test-util` feature in a production build. That feature exists to
  bypass the SSRF guard in tests, and is documented as test-only.
