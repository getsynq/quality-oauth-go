# CLAUDE.md

This is the one implementation of the Coalesce Quality browser login and
credential store. **There must never be a second copy** — not in a consuming
tool, not vendored, not "just the read path". Three near-identical copies is what
this replaced, and the duplication itself caused the bugs: two tools keyed the
store on the API hostname, so whichever logged in first registered the OAuth
client and the other silently reused it and overwrote its token.

Read [README.md](README.md) first. It is the design document, not a summary:
deployment precedence, store layout, locking, and how scope consent accumulates
all live there, each with the failure it prevents.

## Commands

```bash
go build ./...
go test ./...          # includes a re-exec test for the cross-process lock
go test -race ./...
```

## What breaks quietly

- **A credential file is read-modify-written under its sibling `.lock`**, held
  across the re-read, the network call and the write. Shortening that window
  lets two processes both refresh a stale token, and the second writer persists a
  refresh token the server has already rotated away — the user is logged out with
  no error anywhere.
- **Clients are keyed per app, tokens per profile.** Moving either key is the
  original bug: tools share a token slot but must stay separate OAuth clients.
- **An empty recorded scope set means unknown, not none.** Reporting it as
  missing everything tells a working credential it is broken.
- **Only a consented scope set is broadened from.** Unioning claims-derived
  scopes puts a caller's whole role envelope on every consent screen, permanently.
- **`ExpiresAt` is compared with `ExpirySkew` subtracted**, so a token inside that
  window is neither valid nor `Expired()`. Output distinguishes "renewing" from
  "expired"; collapsing the two loses that.
- **`FirstPartyClientID` skips dynamic registration**, so a tool that sets it
  cannot log in against a deployment where its row is absent — and the failure is
  a login that waits for a callback rather than an error. A new tool registers
  dynamically until its row exists everywhere.
- **A Coalesce token's `scope` claim is OIDC scopes.** Recording it as Quality
  scopes reports every scope missing and puts `openid profile …` on the next
  consent screen. `Token.Issuer` is what marks a Coalesce token, and it is what
  routes its refresh away from the deployment's token endpoint.
- **Adding a region is one entry in `regions`.** Every OAuth endpoint is
  discovered per region; none is derived from another region's URL.

## Tests

`authserver_test.go` is a strict fake authorization server — PKCE, registered
redirect URIs, single-use codes, client identity. Keep it strict: a permissive
stub turns a client-side protocol bug into a passing test. Nothing inside the
library is stubbed; the browser is an HTTP client that follows the authorization
URL and its redirect, which is what a real browser does.
