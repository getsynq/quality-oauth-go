package qualityoauth_test

import (
	"os"
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

func TestScopesCoverAndMissing(t *testing.T) {
	granted := []string{"SCOPE_RECON_READ", "SCOPE_RECON_EDIT"}

	require.True(t, qualityoauth.ScopesCover(granted, []string{"SCOPE_RECON_READ"}))
	require.True(t, qualityoauth.ScopesCover(granted, granted))
	require.True(t, qualityoauth.ScopesCover(granted, nil), "needing nothing is always covered")
	require.False(t, qualityoauth.ScopesCover(granted, []string{"SCOPE_INGEST_RECON"}))
	require.False(t, qualityoauth.ScopesCover(nil, []string{"SCOPE_RECON_READ"}))

	require.Empty(t, qualityoauth.MissingScopes(granted, []string{"SCOPE_RECON_READ"}))
	require.Equal(t,
		[]string{"SCOPE_INGEST_RECON", "SCOPE_RECON_PROMOTE"},
		qualityoauth.MissingScopes(granted, []string{"SCOPE_RECON_PROMOTE", "SCOPE_INGEST_RECON", "SCOPE_RECON_READ"}),
		"missing scopes come back sorted and deduplicated")
}

func TestUnionScopesIsSortedAndDeduplicated(t *testing.T) {
	// Union is what makes incremental consent work: broaden the grant rather
	// than replace it with a narrower one.
	require.Equal(t,
		[]string{"SCOPE_INGEST_RECON", "SCOPE_MCP_READ", "SCOPE_RECON_READ"},
		qualityoauth.UnionScopes(
			[]string{"SCOPE_MCP_READ"},
			[]string{"SCOPE_RECON_READ", "SCOPE_INGEST_RECON", "SCOPE_MCP_READ"},
		))

	require.Nil(t, qualityoauth.UnionScopes())
	require.Nil(t, qualityoauth.UnionScopes(nil, []string{"", "  "}))
}

func TestTokenValidityAllowsForClockSkew(t *testing.T) {
	now := time.Now()

	// A token seconds from expiry used to be handed out and then 401.
	inSkew := &qualityoauth.Token{AccessToken: "a", ExpiresAt: now.Add(qualityoauth.ExpirySkew / 2)}
	require.False(t, inSkew.ValidAt(now), "a token inside the skew window is not usable")
	require.False(t, inSkew.Expired(), "…but it has not actually expired yet")

	beyondSkew := &qualityoauth.Token{AccessToken: "a", ExpiresAt: now.Add(2 * qualityoauth.ExpirySkew)}
	require.True(t, beyondSkew.ValidAt(now))

	require.False(t, (&qualityoauth.Token{ExpiresAt: now.Add(time.Hour)}).ValidAt(now),
		"a token with no access token is never valid")

	var missing *qualityoauth.Token
	require.False(t, missing.ValidAt(now))
	require.False(t, missing.Refreshable())

	// No recorded expiry means the server is the authority; refusing it would
	// break a hand-written credential slot.
	require.True(t, (&qualityoauth.Token{AccessToken: "a"}).ValidAt(now))

	require.True(t, (&qualityoauth.Token{RefreshToken: "r"}).Refreshable())
	require.False(t, (&qualityoauth.Token{}).Refreshable())
}

func TestTokenExpired(t *testing.T) {
	require.True(t, (&qualityoauth.Token{AccessToken: "a", ExpiresAt: time.Now().Add(-time.Second)}).Expired())
	require.False(t, (&qualityoauth.Token{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour)}).Expired())
	require.False(t, (&qualityoauth.Token{AccessToken: "a"}).Expired(), "an unknown expiry is not an expired one")
}

func TestCallbackRedirectURIs(t *testing.T) {
	require.Equal(t,
		[]string{"http://127.0.0.1:19876/callback", "http://127.0.0.1:19877/callback", "http://127.0.0.1:19878/callback"},
		qualityoauth.CallbackRedirectURIs(qualityoauth.DefaultCallbackPorts))
	require.Empty(t, qualityoauth.CallbackRedirectURIs(nil))
}

func TestEnvCredentialPrecedence(t *testing.T) {
	// Client credentials are the CI path and win over a static token.
	t.Setenv(qualityoauth.ClientIDEnvVar, "id")
	t.Setenv(qualityoauth.ClientSecretEnvVar, "secret")
	t.Setenv(qualityoauth.TokenEnvVar, "st-token")

	cred := qualityoauth.EnvCredentialFromEnv()
	require.True(t, cred.Found())
	require.Equal(t, qualityoauth.EnvCredentialClient, cred.Kind)
	require.Equal(t, "id", cred.ClientID)
	require.Equal(t, "secret", cred.ClientSecret)

	// A half-set pair is not a credential; applying it would produce a
	// confusing auth failure instead of falling through to the token.
	require.NoError(t, os.Unsetenv(qualityoauth.ClientSecretEnvVar))
	cred = qualityoauth.EnvCredentialFromEnv()
	require.Equal(t, qualityoauth.EnvCredentialToken, cred.Kind)
	require.Equal(t, "st-token", cred.Token)

	require.NoError(t, os.Unsetenv(qualityoauth.ClientIDEnvVar))
	require.NoError(t, os.Unsetenv(qualityoauth.TokenEnvVar))
	cred = qualityoauth.EnvCredentialFromEnv()
	require.False(t, cred.Found())
	require.Equal(t, qualityoauth.EnvCredentialNone, cred.Kind)
}
