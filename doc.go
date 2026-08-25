// Package qualityoauth implements the browser login and shared credential store
// the Coalesce Quality command-line tools use against the public API.
//
// A tool describes itself with an App — its name, a stable software id and the
// scopes it needs — and the package handles the rest: discovering a deployment's
// OAuth endpoints, registering the client, running the authorization-code + PKCE
// flow through a loopback callback, filing the token in a shared on-disk slot and
// refreshing it under a cross-process lock.
//
// Credentials from the environment outrank a stored login, so an unattended run
// never picks up a developer's browser session: a QUALITY_CLIENT_ID and
// QUALITY_CLIENT_SECRET pair first, then a pre-issued QUALITY_TOKEN, then the
// store. Read every such variable through Getenv rather than os.Getenv, which is
// what keeps the older SYNQ_-prefixed spellings working.
//
// The store is shared on purpose: one login serves every tool on the machine.
// See the repository README for its layout, the locking it relies on and how
// scope consent accumulates.
package qualityoauth
