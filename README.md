# quality-oauth-go

[![Go Reference](https://pkg.go.dev/badge/github.com/getsynq/quality-oauth-go.svg)](https://pkg.go.dev/github.com/getsynq/quality-oauth-go)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Go client authentication for the [Coalesce Quality](https://docs.synq.io) public API:
an OAuth 2.0 authorization-code flow with PKCE, client-credentials and static-token
support, and a credential store shared by every command-line tool on the machine.

This is the authentication used by the Coalesce Quality CLIs — `synqctl`,
`synq-recon`, `synq-scout`, `synqcli` — and by the Google Cloud integrations. Any
tool built against the public API can use it and share their credentials: a user
who has logged in with one tool is authenticated for the rest.

## Installation

```bash
go get github.com/getsynq/quality-oauth-go
```

Requires Go 1.25 or later.

## Quick start

Describe the tool once, as an `App`. Everything else follows from it: the OAuth
endpoints for the chosen deployment, client registration, the loopback callback,
token storage and renewal.

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	qualityoauth "github.com/getsynq/quality-oauth-go"
)

var app = qualityoauth.App{
	Name:       "my-integration",
	SoftwareID: "my-integration",
	Scopes:     []string{"SCOPE_ENTITY_READ", "SCOPE_ENTITY_EDIT"},
}

func main() {
	ctx := context.Background()

	// Which deployment to talk to. "" for both arguments falls back to the
	// environment, the last login, and finally the default region.
	target, err := qualityoauth.TargetFromEnv("" /* region */, "" /* endpoint */)
	if err != nil {
		log.Fatal(err)
	}

	// An access token for that deployment, from whichever credential is
	// available. Stored tokens are renewed when stale.
	cred, err := app.Credential(ctx, target)
	if errors.Is(err, qualityoauth.ErrNoCredentials) {
		// Nothing usable on this machine: run the browser login.
		if _, err := app.Login(ctx, target); err != nil {
			log.Fatal(err)
		}
		if cred, err = app.Credential(ctx, target); err != nil {
			log.Fatal(err)
		}
	} else if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cred.Token.AccessToken)
}
```

Send the access token as a bearer token on each API call. With gRPC:

```go
conn, err := grpc.NewClient(target.Endpoint,
	grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
	grpc.WithPerRPCCredentials(bearer(cred.Token.AccessToken)),
	grpc.WithAuthority(target.Host),
)
```

## Credential sources

`App.Credential` resolves credentials in a fixed order. The unattended sources
come first, so a scheduled job does not pick up a developer's interactive login:

1. `QUALITY_CLIENT_ID` + `QUALITY_CLIENT_SECRET` — a client-credentials pair.
2. `QUALITY_TOKEN` — a pre-issued access token, used as given.
3. A token from the credential store, written by a browser login. Expired tokens
   are refreshed transparently.

`ErrNoCredentials` means none of the three yielded a usable token, and the caller
should prompt for a login.

### Browser login

`App.Login` runs the authorization-code flow with PKCE. It registers an OAuth
client for the app on first use, starts a loopback callback server on one of
`DefaultCallbackPorts`, opens a browser, and stores the resulting token.

The authorization URL is logged before the browser is launched, so the flow can be
completed by hand on a machine with no browser available.

`App.Status` lists every stored credential without any network calls — deployment,
profile, workspace, expiry, whether it can be refreshed and which of the app's
scopes it carries. It is what a `<tool> auth status` command prints.
`App.Logout` removes one.

## Environment variables

| Variable | Purpose |
|---|---|
| `QUALITY_CLIENT_ID`, `QUALITY_CLIENT_SECRET` | Client-credentials pair |
| `QUALITY_TOKEN` | Pre-issued access token |
| `QUALITY_API_ENDPOINT` | API endpoint as `host:port`, overriding the region |
| `QUALITY_REGION` | Deployment region name |
| `QUALITY_AUTH_PROFILE` | Credential slot to use instead of `shared` |
| `QUALITY_HOME` | Base directory for the store, instead of `~/.synq` |

Each variable has a `SYNQ_`-prefixed predecessor that is still honoured for
compatibility. Read these values with `qualityoauth.Getenv` rather than
`os.Getenv` so the fallback applies.

## Choosing a deployment

A `Target` is either a named region or an explicit `host:port` endpoint.
`RegionNames` lists the regions; `TargetForRegion` and `TargetForEndpoint`
construct targets directly.

Every OAuth endpoint — issuer, authorization, token, registration — is discovered
from the deployment's own `/.well-known/oauth-authorization-server` document
rather than derived from another deployment's URL, because the issuer differs per
region.

`Sources.Resolve` implements the precedence, highest first:

1. an explicit endpoint (typically an `--endpoint` flag)
2. a region (`--region`)
3. an endpoint from the tool's own configuration file
4. `QUALITY_API_ENDPOINT`
5. `QUALITY_REGION`
6. the deployment of the most recent successful login
7. `DefaultRegion`

Tier 6 is why a user whose only deployment is not the default never has to pass
`--region`: it sits below every explicit source, so it only applies where the
default region would otherwise have been assumed silently.

## Credential storage

```
~/.synq/credentials.json                          index of known deployments
~/.synq/oauth/<host>/clients/<app>.json           OAuth client registration, per app
~/.synq/oauth/<host>/<profile>/token.json         access and refresh token
~/.synq/oauth/<host>/<profile>/token-<flow>.json  token for an alternate flow
```

- **Tokens are partitioned by host**, so a token minted for one region is never
  sent to another.
- **Profiles** separate credential slots. The default is `shared`, which is what
  allows one login to serve every tool; `WithIsolated()` or
  `QUALITY_AUTH_PROFILE` gives a tool its own slot.
- **Client registrations are per app**, outside the profile. Tools sharing a
  token slot remain distinct OAuth clients, and a stored token records the client
  that minted it so refreshes present the right one.
- The index is a convenience for enumeration. Credential resolution reads the
  directory tree, so a missing or stale index entry never hides a credential.

Directories are created with mode `0700` and token files with `0600` on
Unix-like systems. Windows has no equivalent permission bits; there the store is
protected by the access control list of its parent directory.

Every credential file is read and written under an advisory lock held for the
whole operation, including the token refresh request. Two processes that both see
a stale token therefore refresh in sequence rather than concurrently, which
prevents one of them persisting a refresh token the server has already rotated.
In-process mutexes layer on top, because goroutines in a single process share
file descriptors and would not be serialised by the OS lock alone.

## Scopes

An app declares the scopes it needs and the login requests exactly those. A login
that requests none receives whatever the user's role permits, which is wider than
a tool should hold.

- Consent is incremental. A login for an app requesting a new scope asks for the
  union of what has been consented to and what is needed, so re-consenting
  broadens an existing shared grant rather than narrowing it.
- Adding a scope to an app requires only a new login. Nothing caches the
  previously requested set.
- A stored token with no recorded scopes means the set is unknown, not empty.
  `Status.CoversScopes` reports `true` for such a credential rather than
  declaring it insufficient.
- Scopes recovered from an access token's claims, as opposed to a recorded
  consent, are reported but never re-requested.

## Development

```bash
go build ./...
go test ./...        # includes a re-exec test covering the cross-process lock
go test -race ./...
```

Tests run against a strict in-process authorization server that enforces PKCE,
registered redirect URIs, single-use authorization codes and client identity.
Nothing inside the library is stubbed; the browser step is performed by an HTTP
client that follows the authorization URL and its redirect.

## Support

Coalesce Quality documentation: <https://docs.synq.io>.

## License

Apache 2.0 — see [LICENSE](LICENSE).
