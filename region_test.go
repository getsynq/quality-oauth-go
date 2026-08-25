package qualityoauth_test

import (
	"testing"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

func TestNamedRegionsResolveToTheirOwnEndpoints(t *testing.T) {
	cases := map[string]struct {
		endpoint string
		host     string
	}{
		"eu": {endpoint: "developer.synq.io:443", host: "developer.synq.io"},
		"us": {endpoint: "api.us.synq.io:443", host: "api.us.synq.io"},
		"au": {endpoint: "api.au.synq.io:443", host: "api.au.synq.io"},
	}

	require.ElementsMatch(t, []string{"au", "eu", "us"}, qualityoauth.RegionNames())

	for name, want := range cases {
		target, err := qualityoauth.TargetForRegion(name)
		require.NoError(t, err, name)
		require.Equal(t, name, target.Region)
		require.Equal(t, want.endpoint, target.Endpoint)
		require.Equal(t, want.host, target.Host)
		require.Equal(t, "https://"+want.host, target.AuthServerBaseURL(),
			"the discovery document is always fetched from the region's own host")
	}

	// Every region has a distinct store partition, which is what stops one
	// region's token from overwriting another's.
	hosts := map[string]string{}
	for name := range cases {
		target, err := qualityoauth.TargetForRegion(name)
		require.NoError(t, err)
		require.NotContains(t, hosts, target.Host)
		hosts[target.Host] = name
	}
}

func TestUnknownRegionIsRejectedWithTheKnownNames(t *testing.T) {
	_, err := qualityoauth.TargetForRegion("mars")
	require.Error(t, err)
	require.ErrorContains(t, err, `unknown region "mars"`)
	require.ErrorContains(t, err, "au, eu, us")
}

func TestEndpointsAreNormalisedToHostPort(t *testing.T) {
	// The per-region fe-app env files disagree on scheme and port, so the CLIs
	// accept every shape rather than making the user know which.
	for _, in := range []string{
		"developer.synq.io:443",
		"developer.synq.io",
		"https://developer.synq.io",
		"https://developer.synq.io:443",
		"https://developer.synq.io:443/",
	} {
		target := qualityoauth.TargetForEndpoint(in)
		require.Equal(t, "developer.synq.io:443", target.Endpoint, in)
		require.Equal(t, "developer.synq.io", target.Host, in)
		require.Equal(t, "eu", target.Region, "a known endpoint is recognised as its region: %s", in)
	}

	// http defaults to port 80, for a local authorization server.
	require.Equal(t, "localhost:80", qualityoauth.TargetForEndpoint("http://localhost").Endpoint)
	require.Equal(t, "localhost:8080", qualityoauth.TargetForEndpoint("http://localhost:8080").Endpoint)
}

func TestLoopbackTargetsUseHTTP(t *testing.T) {
	// A local authorization server is served over plain HTTP; forcing https would make
	// local development impossible.
	require.Equal(t, "http://localhost:8080", qualityoauth.TargetForEndpoint("localhost:8080").AuthServerBaseURL())
	require.Equal(t, "http://127.0.0.1:9000", qualityoauth.TargetForEndpoint("127.0.0.1:9000").AuthServerBaseURL())
	require.Equal(t, "https://developer.synq.dev", qualityoauth.TargetForEndpoint("developer.synq.dev:443").AuthServerBaseURL())
}

func TestSelfHostedEndpointHasNoRegion(t *testing.T) {
	target := qualityoauth.TargetForEndpoint("api.internal.example:8443")
	require.Empty(t, target.Region)
	require.Equal(t, "api.internal.example", target.Host)
	require.Equal(t, "api.internal.example:8443", target.String())
}

func TestResolveTargetPrecedence(t *testing.T) {
	// The default region applies when nothing is given.
	target, err := qualityoauth.ResolveTarget("", "")
	require.NoError(t, err)
	require.Equal(t, "eu", target.Region)

	// A region name selects that region.
	target, err = qualityoauth.ResolveTarget("us", "")
	require.NoError(t, err)
	require.Equal(t, "api.us.synq.io:443", target.Endpoint)

	// An explicit endpoint is the escape hatch for staging and self-hosted.
	target, err = qualityoauth.ResolveTarget("", "developer.synq.dev:443")
	require.NoError(t, err)
	require.Equal(t, "developer.synq.dev:443", target.Endpoint)
	require.Empty(t, target.Region)

	// Naming a region and an endpoint that agree is fine, and lands in one slot.
	target, err = qualityoauth.ResolveTarget("us", "https://api.us.synq.io")
	require.NoError(t, err)
	require.Equal(t, "us", target.Region)

	// Naming a region and a contradicting endpoint is a mistake worth failing
	// on: silently picking one would send a token to the wrong region.
	_, err = qualityoauth.ResolveTarget("us", "developer.synq.io:443")
	require.Error(t, err)
	require.ErrorContains(t, err, "pass only one")

	_, err = qualityoauth.ResolveTarget("mars", "")
	require.Error(t, err)
}

func TestTargetFromEnvFallsBackToEnvironment(t *testing.T) {
	clearDeploymentEnv(t)
	t.Setenv(qualityoauth.RegionEnvVar, "us")
	target, err := qualityoauth.TargetFromEnv("", "")
	require.NoError(t, err)
	require.Equal(t, "us", target.Region)

	// A flag beats the environment.
	target, err = qualityoauth.TargetFromEnv("eu", "")
	require.NoError(t, err)
	require.Equal(t, "eu", target.Region)

	// An endpoint in the environment beats a region in the environment, so a
	// staging endpoint keeps working when a region is also exported.
	t.Setenv(qualityoauth.EndpointEnvVar, "developer.synq.dev:443")
	target, err = qualityoauth.TargetFromEnv("", "")
	require.NoError(t, err)
	require.Equal(t, "developer.synq.dev:443", target.Endpoint)
}

func TestTargetFlowGetsItsOwnIdentity(t *testing.T) {
	base, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	internal := base.WithFlow(qualityoauth.FlowInternal)

	require.Empty(t, base.Flow)
	require.Equal(t, qualityoauth.FlowInternal, internal.Flow)
	require.Equal(t, base.Host, internal.Host, "the flow does not change which region we talk to")
	require.Equal(t, "eu (developer.synq.io:443)", base.String())
}

func TestOAuthTokenURL(t *testing.T) {
	eu, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	require.Equal(t, "https://developer.synq.io/oauth2/token", qualityoauth.OAuthTokenURL(eu))
	require.Equal(t,
		"http://localhost:8080/oauth2/token",
		qualityoauth.OAuthTokenURL(qualityoauth.TargetForEndpoint("localhost:8080")))
}
