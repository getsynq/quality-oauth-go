# Coalesce Quality OAuth for Go

The browser login (OAuth 2.0 authorization code + PKCE) and shared credential
store that the Coalesce Quality command-line tools use against the public API.

It is one implementation, deliberately. The tools that use it — `synqctl`,
`synq-recon`, `synq-scout`, `synqcli`, and the Google Cloud integrations — share
a credential slot on disk, so a login with one of them authenticates the rest.
Reimplementing any part of that per tool is what this package exists to prevent:
three near-identical copies keyed their OAuth client registration on the API
hostname, so whichever tool logged in first registered the client and the others
silently reused it and overwrote its token.

```bash
go get github.com/getsynq/quality-oauth-go
```

## Using it

An app declares who it is and what it needs. Everything else — the region's
OAuth endpoints, the client registration, the callback server, the token
refresh, where the credential is filed — follows from that.

```go
package main

import (
	"context"
	"fmt"

	qualityoauth "github.com/getsynq/quality-oauth-go"
)

var app = qualityoauth.App{
	Name:       "my-integration",
	SoftwareID: "my-integration",
	Scopes:     []string{"SCOPE_ENTITY_EDIT", "SCOPE_LINEAGE_EDIT"},
}

func main() {
	ctx := context.Background()

	// Where to talk to: --region / --endpoint flags, then the QUALITY_*
	// environment, then the deployment of the last successful login.
	target, err := qualityoauth.TargetFromEnv("us", "")
	if err != nil {
		panic(err)
	}

	// A browser login. Prints the authorization URL before opening a browser,
	// so a headless machine still has a way through.
	if _, err := app.Login(ctx, target); err != nil {
		panic(err)
	}

	// Later runs need only this: a stored token is refreshed when stale, and a
	// client-credential or pre-issued token in the environment wins over it.
	cred, err := app.Credential(ctx, target)
	if err != nil {
		panic(err)
	}
	fmt.Println(cred.Source, cred.Token.AccessToken != "")
}
```

`app.Status(ctx)` reports every credential on the machine — deployment, profile,
flow, whether it is valid, refreshable or expired, and which of the app's scopes
are missing. That is what a `<tool> auth status` command prints.

## Deployments

A deployment is a region name or an explicit endpoint. Regions are listed by
`RegionNames()` and resolved by `TargetForRegion`; every OAuth endpoint (issuer,
authorize, token, registration) is discovered from that region's own
`/.well-known/oauth-authorization-server` rather than derived from another
region's URL, because the issuer differs per region.

`Sources.Resolve` is the single implementation of the precedence, highest first:

1. `--endpoint`, then `--region`
2. `QUALITY_API_ENDPOINT`, then `QUALITY_REGION`
3. the deployment recorded by the last successful login
4. the default region

Recording the last login is what lets someone whose only deployment is AU never
type `--region`. It sits below every explicit source, so it can only change an
invocation that would otherwise have silently assumed EU.

## Environment variables

The `QUALITY_*` names are the documented ones. Each has a `SYNQ_`-prefixed
predecessor that is still read, because they are in existing CI configuration
and `.env` files.

| Variable | What it does |
|---|---|
| `QUALITY_CLIENT_ID` + `QUALITY_CLIENT_SECRET` | Client-credential pair. Unattended, and wins over a stored login. |
| `QUALITY_TOKEN` | A pre-issued access token, used as-is. |
| `QUALITY_API_ENDPOINT` | `host:port` of the API, overriding the region. |
| `QUALITY_REGION` | Region name. |
| `QUALITY_AUTH_PROFILE` | Credential slot to use instead of `shared`. |
| `QUALITY_HOME` | Where the store lives, instead of `~/.synq`. |

Read them through `qualityoauth.Getenv`, never `os.Getenv`, or that one setting
stops honouring its alias.

## Store layout

```
~/.synq/credentials.json                          index (convenience, not truth)
~/.synq/oauth/<host>/clients/<app>.json           per-app client registration
~/.synq/oauth/<host>/<profile>/token.json         standard-flow token
~/.synq/oauth/<host>/<profile>/token-<flow>.json  alternate-flow token
```

- **Host partition** keeps the regions apart: a token minted for one region must
  never be sent to another.
- **Profile partition** is `shared` by default, so one login serves the whole
  toolchain. `WithIsolated()` or `QUALITY_AUTH_PROFILE` gives a tool its own slot.
- **Clients sit outside the profile, one per app.** Several tools share a token
  slot but each stays its own OAuth client, or a second login overwrites the
  first tool's identity and its refresh stops working. A token records the
  `client_id` that minted it and a refresh presents *that* client.
- **The index is a convenience.** A missing or stale entry never hides a
  credential that is on disk; resolution reads the directory tree.

Every credential file has an advisory sibling `.lock`, held for the whole
read-modify-write including the network call. Atomic writes alone are not enough:
two processes both seeing a stale token would both refresh, and the second writer
would persist a refresh token the server has already rotated away — silently
logging the user out. In-process mutexes are layered on top, because goroutines
in one process share a file descriptor table and the OS lock alone would not
serialise them.

## Scopes

An app declares what it needs and the login sends it as the `scope` parameter.
Not sending it is what gives a two-permission tool a forty-permission token.

- An **empty** recorded scope set means *unknown*, not *none*. It is what a
  credential adopted from an older store looks like; never report it as missing
  everything.
- Consent is incremental: a login asks for `consented ∪ needed`, so re-consenting
  broadens a shared grant instead of narrowing it.
- Only a **consented** set is broadened from. Scopes recovered from an access
  token's own claims are reported as what the token carries but never
  re-requested — the older flow sent no `scope`, so the claim is the caller's
  whole role-derived envelope, and unioning it would put every permission on
  every tool's consent screen permanently. A refresh inherits provenance;
  renewing is not consenting.
- Declaring a new scope needs nothing but a re-login. Nothing caches what was
  once asked for, and the `scope` on a cached client registration is metadata
  only.

## Development

```bash
go build ./...
go test ./...
```

`authserver_test.go` is a strict fake authorization server: it enforces PKCE,
registered redirect URIs, single-use codes and client identity. Keep it strict —
a permissive stub turns a client-side protocol bug into a passing test. The
browser is stubbed by an HTTP client that follows the authorization URL and its
redirect, which is what a real browser does; nothing inside the library itself is
stubbed. `concurrency_test.go` re-execs the test binary to prove the file lock is
really cross-process, because a goroutine-only test would pass while the real
thing raced.

## Support

Coalesce Quality documentation: <https://docs.synq.io>.

## License

Apache 2.0. See [LICENSE](LICENSE).
