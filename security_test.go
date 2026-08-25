package qualityoauth_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

// hostileEndpoints are endpoint values that must never be accepted, because the
// host becomes a directory name in the credential store.
//
// The endpoint is not always under the user's eye: it comes from
// --endpoint, QUALITY_API_ENDPOINT, or a .env file that
// synq-monitors reads from the working directory — so a cloned repository can set
// it. Before validation, ".." resolved to a host of ".." and wrote the token a
// directory above the store, and on Windows a host containing a backslash escaped
// several levels because filepath treats it as a separator there.
var hostileEndpoints = []string{
	"..:443",
	"../../etc:443",
	"https://../evil",
	`..\..\evil:443`,
	`..\..\..\Users\victim\.ssh:443`,
	".:443",
	// A host that is present but empty, as opposed to no endpoint at all.
	":443",
	"host with spaces:443",
}

func TestResolveTargetRejectsHostileEndpoints(t *testing.T) {
	for _, endpoint := range hostileEndpoints {
		t.Run(endpoint, func(t *testing.T) {
			_, err := qualityoauth.ResolveTarget("", endpoint)
			require.Error(t, err, "endpoint %q must be rejected", endpoint)
		})
	}
}

func TestTargetFromEnvRejectsHostileEndpoints(t *testing.T) {
	for _, endpoint := range hostileEndpoints {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv(qualityoauth.EndpointEnvVar, endpoint)
			t.Setenv(qualityoauth.RegionEnvVar, "")
			_, err := qualityoauth.TargetFromEnv("", "")
			require.Error(t, err, "QUALITY_API_ENDPOINT=%q must be rejected", endpoint)
		})
	}
}

// TestAnAbsentEndpointIsNotHostile: an empty value means "not given" and falls
// back to the default region, which is not the same as a malformed one.
func TestAnAbsentEndpointIsNotHostile(t *testing.T) {
	t.Setenv(qualityoauth.EndpointEnvVar, "")
	t.Setenv(qualityoauth.RegionEnvVar, "")

	target, err := qualityoauth.ResolveTarget("", "")
	require.NoError(t, err)
	require.Equal(t, qualityoauth.DefaultRegion, target.Region)

	target, err = qualityoauth.TargetFromEnv("", "")
	require.NoError(t, err)
	require.Equal(t, qualityoauth.DefaultRegion, target.Region)
}

// TestStoreRefusesToWriteOutsideItself is the defence-in-depth layer: even a
// Target built directly, bypassing ResolveTarget, must not be able to place a
// credential outside the store.
func TestStoreRefusesToWriteOutsideItself(t *testing.T) {
	root := t.TempDir()
	store := qualityoauth.NewStore(root)
	tok := &qualityoauth.Token{AccessToken: "secret", ExpiresAt: time.Now().Add(time.Hour)}

	for _, host := range []string{"..", ".", "", "a/../..", `..\..`, "evil/../.."} {
		target := qualityoauth.Target{Host: host, Endpoint: host}

		require.Error(t, store.SaveToken(target, qualityoauth.SharedProfile, tok), "host %q", host)
		_, err := store.LoadToken(target, qualityoauth.SharedProfile)
		require.Error(t, err, "host %q", host)
		_, err = store.LockToken(target, qualityoauth.SharedProfile)
		require.Error(t, err, "host %q", host)
		require.Error(t,
			store.SaveClient(target, "synq-recon", &qualityoauth.ClientRegistration{ClientID: "c"}), "host %q", host)
		_, err = store.DeleteToken(target, qualityoauth.SharedProfile)
		require.Error(t, err, "host %q", host)
	}

	// Nothing was created anywhere under or beside the store.
	var found []string
	require.NoError(t, filepath.Walk(filepath.Dir(root), func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // a sibling temp dir we cannot read is not our concern
		}
		base := filepath.Base(path)
		if strings.Contains(base, "token") || strings.Contains(base, "client") {
			found = append(found, path)
		}
		return nil
	}))
	require.Empty(t, found, "a rejected write must leave no credential file behind")
}

// TestStoreRefusesAHostileProfile covers the other user-supplied path component,
// --auth-profile / SYNQ_AUTH_PROFILE.
func TestStoreRefusesAHostileProfile(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	tok := &qualityoauth.Token{AccessToken: "secret"}

	for _, profile := range []string{"..", ".", "", "../escape", `..\escape`, "a/b", "clients"} {
		require.Error(t, store.SaveToken(target, profile, tok), "profile %q", profile)
		_, err := store.LoadToken(target, profile)
		require.Error(t, err, "profile %q", profile)
	}
}

// TestStoreRefusesAHostileFlow covers the flow, which becomes part of a filename
// (token-<flow>.json).
func TestStoreRefusesAHostileFlow(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	base, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	for _, flow := range []string{"../escape", "a/b", `..\b`, ".."} {
		target := base.WithFlow(flow)
		require.Error(t,
			store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{AccessToken: "s"}), "flow %q", flow)
	}

	// The one flow we actually use stays valid.
	require.NoError(t, store.SaveToken(base.WithFlow(qualityoauth.FlowInternal), qualityoauth.SharedProfile,
		&qualityoauth.Token{AccessToken: "s"}))
}

// TestLegitimateHostsStillResolve guards against the validation being too strict —
// IPv6 literals and explicit ports in particular.
func TestLegitimateHostsStillResolve(t *testing.T) {
	for _, endpoint := range []string{
		"developer.synq.io:443",
		"api.us.synq.io:443",
		"api.au.synq.io:443",
		"developer.synq.dev:443",
		"localhost:8080",
		"127.0.0.1:9000",
		"https://api.internal.example:8443",
		"internal-host.corp.example.com:443",
	} {
		t.Run(endpoint, func(t *testing.T) {
			target, err := qualityoauth.ResolveTarget("", endpoint)
			require.NoError(t, err)
			require.NoError(t, target.Validate())

			// And the resolved slot really is inside the store.
			store := qualityoauth.NewStore("/home/u/.synq")
			path := store.TokenPath(target, qualityoauth.SharedProfile)
			require.True(t, strings.HasPrefix(filepath.Clean(path), "/home/u/.synq/oauth/"),
				"token path %q escaped the store", path)
		})
	}
}

// TestATokenIsNeverReadFromAnotherRegionsSlot is the property the region partition
// exists for. A hijacked endpoint — set through a .env in an untrusted repository,
// say — must not be able to pick up a credential minted for a real region.
func TestATokenIsNeverReadFromAnotherRegionsSlot(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	app := qualityoauth.App{Name: "synq-recon", Scopes: []string{"SCOPE_RECON_READ"}}
	opts := []qualityoauth.Option{qualityoauth.WithStore(store)}
	t.Setenv(qualityoauth.AuthProfileEnvVar, "")

	eu, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(eu, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken:  "eu-secret",
		RefreshToken: "eu-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}))

	// A syntactically valid but attacker-chosen endpoint gets its own empty slot.
	evil, err := qualityoauth.ResolveTarget("", "evil.example:443")
	require.NoError(t, err)
	require.False(t, app.HasStoredCredential(evil, nil, opts...),
		"an attacker-chosen endpoint must not inherit a real region's credential")

	tok, err := store.LoadToken(evil, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.Nil(t, tok)

	// The real region is untouched and still usable.
	require.True(t, app.HasStoredCredential(eu, nil, opts...))
}
