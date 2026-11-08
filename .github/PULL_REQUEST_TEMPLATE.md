<!-- Thanks! A pull request here is squash-merged, so the title becomes the commit
     subject on main: say what it does, in the imperative. -->

## What and why

<!-- What changes, and why. For a bug: how it was established, not assumed. Link the issue. -->

## Checklist

- [ ] `scripts/ci.sh` ends in `ci: all green` locally
- [ ] A test fails without this change. For a fix, I checked by reverting it **where it's
      called**, not only in a helper.
- [ ] `CHANGELOG.md` has an entry under *Unreleased* (and under *Upgrade notes* if it breaks an
      API or raises the MSRV)
- [ ] Public items have doc comments: what they do, what they refuse, and why
- [ ] If this touches `net`, `dpop`, `client_auth`, `keys`, `jwt`, `token` or `revoke`:
      `cargo mutants --in-diff` run, and any surviving mutants listed below with a reason

## Surviving mutants (if any)

<!-- e.g. "net.rs:812 replace `<` with `<=`: equivalent, the cap is exclusive both ways". -->
