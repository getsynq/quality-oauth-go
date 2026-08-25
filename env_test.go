package qualityoauth_test

import (
	"testing"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

// clearDeploymentEnv unsets both spellings of every setting that steers
// resolution, so a test observes what it sets and not what the developer's
// shell happens to export.
func clearDeploymentEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		qualityoauth.EndpointEnvVar,
		qualityoauth.RegionEnvVar,
		qualityoauth.ClientIDEnvVar,
		qualityoauth.ClientSecretEnvVar,
		qualityoauth.TokenEnvVar,
	} {
		t.Setenv(name, "")
		if legacy, ok := qualityoauth.DeprecatedEnvVar(name); ok {
			t.Setenv(legacy, "")
		}
	}
}

func TestPromotedEnvVarsAreBrandNeutral(t *testing.T) {
	// The names in help text, documentation and new configuration.
	require.Equal(t, "QUALITY_REGION", qualityoauth.RegionEnvVar)
	require.Equal(t, "QUALITY_API_ENDPOINT", qualityoauth.EndpointEnvVar)
	require.Equal(t, "QUALITY_CLIENT_ID", qualityoauth.ClientIDEnvVar)
	require.Equal(t, "QUALITY_CLIENT_SECRET", qualityoauth.ClientSecretEnvVar)
	require.Equal(t, "QUALITY_TOKEN", qualityoauth.TokenEnvVar)
	require.Equal(t, "QUALITY_AUTH_PROFILE", qualityoauth.AuthProfileEnvVar)
	require.Equal(t, "QUALITY_HOME", qualityoauth.HomeDirEnvVar)
}

func TestDeprecatedEnvVarsAreStillHonoured(t *testing.T) {
	clearDeploymentEnv(t)

	// A pipeline that has only ever set the SYNQ_ names keeps working.
	t.Setenv("SYNQ_REGION", "us")
	require.Equal(t, "us", qualityoauth.Getenv(qualityoauth.RegionEnvVar))

	target, err := qualityoauth.Sources{Store: qualityoauth.NewStore(t.TempDir())}.Resolve()
	require.NoError(t, err)
	require.Equal(t, "us", target.Region)

	// The promoted name wins where both are set, so a machine can be migrated
	// one variable at a time.
	t.Setenv(qualityoauth.RegionEnvVar, "au")
	target, err = qualityoauth.Sources{Store: qualityoauth.NewStore(t.TempDir())}.Resolve()
	require.NoError(t, err)
	require.Equal(t, "au", target.Region)
}

func TestEnvCredentialReadsEitherSpelling(t *testing.T) {
	clearDeploymentEnv(t)

	t.Setenv("SYNQ_CLIENT_ID", "legacy-id")
	t.Setenv("SYNQ_CLIENT_SECRET", "legacy-secret")
	cred := qualityoauth.EnvCredentialFromEnv()
	require.Equal(t, qualityoauth.EnvCredentialClient, cred.Kind)
	require.Equal(t, "legacy-id", cred.ClientID)

	t.Setenv(qualityoauth.ClientIDEnvVar, "new-id")
	cred = qualityoauth.EnvCredentialFromEnv()
	require.Equal(t, "new-id", cred.ClientID)
	require.Equal(t, "legacy-secret", cred.ClientSecret, "one variable at a time must work")

	clearDeploymentEnv(t)
	t.Setenv("SYNQ_TOKEN", "st-legacy")
	cred = qualityoauth.EnvCredentialFromEnv()
	require.Equal(t, qualityoauth.EnvCredentialToken, cred.Kind)
	require.Equal(t, "st-legacy", cred.Token)
}

func TestHomeOverrideReadsEitherSpelling(t *testing.T) {
	t.Setenv(qualityoauth.HomeDirEnvVar, "")
	t.Setenv("SYNQ_HOME", t.TempDir()+"/legacy")
	store, err := qualityoauth.DefaultStore()
	require.NoError(t, err)
	require.Contains(t, store.Root(), "legacy")

	promoted := t.TempDir() + "/promoted"
	t.Setenv(qualityoauth.HomeDirEnvVar, promoted)
	store, err = qualityoauth.DefaultStore()
	require.NoError(t, err)
	require.Equal(t, promoted, store.Root())
}
