package qualityoauth_test

import (
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

// storeWithToken returns a store rooted at a temp dir holding one token for the
// named region, which is the state a successful login leaves behind.
func storeWithToken(t *testing.T, region string) (*qualityoauth.Store, qualityoauth.Target) {
	t.Helper()
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion(region)
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	return store, target
}

func TestDefaultTargetIsAbsentUntilRecorded(t *testing.T) {
	store, _ := storeWithToken(t, "au")

	_, ok, err := store.DefaultTarget()
	require.NoError(t, err)
	require.False(t, ok, "storing a token is not by itself a choice of deployment")
}

func TestDefaultTargetRoundTrips(t *testing.T) {
	store, au := storeWithToken(t, "au")
	require.NoError(t, store.SetDefaultTarget(au))

	got, ok, err := store.DefaultTarget()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "au", got.Region)
	require.Equal(t, "api.au.synq.io:443", got.Endpoint)
}

func TestLoggingOutOfTheRememberedDeploymentForgetsIt(t *testing.T) {
	store, au := storeWithToken(t, "au")
	require.NoError(t, store.SetDefaultTarget(au))

	removed, err := store.DeleteToken(au, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.True(t, removed)

	_, ok, err := store.DefaultTarget()
	require.NoError(t, err)
	require.False(t, ok, "logging out of the remembered deployment must not leave it remembered")
}

func TestLoggingOutOfOneRegionKeepsAnotherRegionsDefault(t *testing.T) {
	store, au := storeWithToken(t, "au")
	us, err := qualityoauth.TargetForRegion("us")
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(us, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.SetDefaultTarget(au))

	_, err = store.DeleteToken(us, qualityoauth.SharedProfile)
	require.NoError(t, err)

	got, ok, err := store.DefaultTarget()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "au", got.Region)
}

func TestForgetDefaultTargetReportsWhetherThereWasOne(t *testing.T) {
	store, au := storeWithToken(t, "au")

	had, err := store.ForgetDefaultTarget()
	require.NoError(t, err)
	require.False(t, had)

	require.NoError(t, store.SetDefaultTarget(au))
	had, err = store.ForgetDefaultTarget()
	require.NoError(t, err)
	require.True(t, had)

	_, ok, err := store.DefaultTarget()
	require.NoError(t, err)
	require.False(t, ok)
}

func TestDefaultTargetSurvivesACustomEndpoint(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	staging := qualityoauth.TargetForEndpoint("developer.synq.dev:443")
	require.NoError(t, store.SaveToken(staging, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.SetDefaultTarget(staging))

	got, ok, err := store.DefaultTarget()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "developer.synq.dev:443", got.Endpoint)
	require.Empty(t, got.Region)
}

func TestSourcesPrecedence(t *testing.T) {
	// Every tier below the flags reads the environment, so pin it: an exported
	// QUALITY_REGION on the developer's machine would otherwise decide the
	// result.
	clearDeploymentEnv(t)
	store, au := storeWithToken(t, "au")
	require.NoError(t, store.SetDefaultTarget(au))

	sources := func(mutate func(*qualityoauth.Sources)) qualityoauth.Sources {
		s := qualityoauth.Sources{Store: store}
		mutate(&s)
		return s
	}

	// The remembered deployment beats the default region, which is the whole
	// point: one login to AU and no later command needs --region.
	target, err := sources(func(*qualityoauth.Sources) {}).Resolve()
	require.NoError(t, err)
	require.Equal(t, "au", target.Region)

	// A region in the environment is something the user set for this shell, so
	// it wins over the remembered one.
	t.Setenv(qualityoauth.RegionEnvVar, "us")
	target, err = sources(func(*qualityoauth.Sources) {}).Resolve()
	require.NoError(t, err)
	require.Equal(t, "us", target.Region)

	// An endpoint in the environment is more specific than a region in it.
	t.Setenv(qualityoauth.EndpointEnvVar, "developer.synq.dev:443")
	target, err = sources(func(*qualityoauth.Sources) {}).Resolve()
	require.NoError(t, err)
	require.Equal(t, "developer.synq.dev:443", target.Endpoint)

	// Configuration a CLI already honours — a suite's endpoint, a .env file —
	// beats the environment but loses to either flag.
	target, err = sources(func(s *qualityoauth.Sources) { s.ConfiguredEndpoint = "api.us.synq.io:443" }).Resolve()
	require.NoError(t, err)
	require.Equal(t, "us", target.Region)

	target, err = sources(func(s *qualityoauth.Sources) {
		s.ConfiguredEndpoint = "api.us.synq.io:443"
		s.RegionFlag = "eu"
	}).Resolve()
	require.NoError(t, err)
	require.Equal(t, "eu", target.Region)

	_, err = sources(func(s *qualityoauth.Sources) {
		s.RegionFlag = "eu"
		s.EndpointFlag = "developer.synq.dev:443"
	}).Resolve()
	require.Error(t, err, "two flags naming different deployments is a mistake, not a precedence question")
	require.ErrorContains(t, err, "pass only one")
}

func TestSourcesRejectAConfiguredEndpointThatEscapesTheStore(t *testing.T) {
	clearDeploymentEnv(t)
	_, err := qualityoauth.Sources{
		Store:              qualityoauth.NewStore(t.TempDir()),
		ConfiguredEndpoint: "../evil:443",
	}.Resolve()
	require.Error(t, err)
	require.ErrorContains(t, err, "configured endpoint")
}

func TestSourcesFallBackToTheDefaultRegionWithNothingStored(t *testing.T) {
	clearDeploymentEnv(t)
	target, err := qualityoauth.Sources{Store: qualityoauth.NewStore(t.TempDir())}.Resolve()
	require.NoError(t, err)
	require.Equal(t, qualityoauth.DefaultRegion, target.Region)
}
