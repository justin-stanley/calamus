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

Status: **no code here yet.** The plan is [`design/EXTRACTION.md`](design/EXTRACTION.md).
