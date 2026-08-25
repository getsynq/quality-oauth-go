package qualityoauth_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

func TestStorePathsPartitionByHostProfileAndFlow(t *testing.T) {
	store := qualityoauth.NewStore("/tmp/creds")
	eu, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	us, err := qualityoauth.TargetForRegion("us")
	require.NoError(t, err)

	require.Equal(t,
		filepath.Join("/tmp/creds", "oauth", "developer.synq.io", "shared", "token.json"),
		store.TokenPath(eu, qualityoauth.SharedProfile))
	require.Equal(t,
		filepath.Join("/tmp/creds", "oauth", "api.us.synq.io", "shared", "token.json"),
		store.TokenPath(us, qualityoauth.SharedProfile))
	require.Equal(t,
		filepath.Join("/tmp/creds", "oauth", "developer.synq.io", "synq-recon", "token.json"),
		store.TokenPath(eu, "synq-recon"))
	require.Equal(t,
		filepath.Join("/tmp/creds", "oauth", "developer.synq.io", "shared", "token-internal.json"),
		store.TokenPath(eu.WithFlow(qualityoauth.FlowInternal), qualityoauth.SharedProfile))

	// Client registrations sit beside the profiles, one per app, so two tools
	// can share a token slot and still be distinct clients.
	require.Equal(t,
		filepath.Join("/tmp/creds", "oauth", "developer.synq.io", "clients", "synq-recon.json"),
		store.ClientPath(eu, "synq-recon"))
}

func TestStoreRoundTripsTokensAndStampsTheTarget(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("us")
	require.NoError(t, err)

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "access",
		ExpiresAt:   expiry,
		Scopes:      []string{"SCOPE_RECON_READ"},
		Workspace:   "acme",
	}))

	got, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "access", got.AccessToken)
	require.Equal(t, "acme", got.Workspace)
	require.Equal(t, "us", got.Region, "the region is stamped so status reads offline")
	require.Equal(t, "api.us.synq.io:443", got.Endpoint)
	require.WithinDuration(t, expiry, got.ExpiresAt, time.Second)
	require.False(t, got.UpdatedAt.IsZero())
}

func TestStoreMissingCredentialIsNotAnError(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	tok, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.Nil(t, tok)

	client, err := store.LoadClient(target, "synq-recon")
	require.NoError(t, err)
	require.Nil(t, client)

	profiles, err := store.Profiles(target)
	require.NoError(t, err)
	require.Empty(t, profiles)

	hosts, err := store.Hosts()
	require.NoError(t, err)
	require.Empty(t, hosts)

	statuses, err := store.Status(context.Background())
	require.NoError(t, err)
	require.Empty(t, statuses)
}

func TestStoreDirectoriesAreOwnerOnly(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{AccessToken: "a"}))

	for _, dir := range []string{
		filepath.Join(store.Root(), "oauth"),
		filepath.Join(store.Root(), "oauth", target.Host),
		store.ProfileDir(target, qualityoauth.SharedProfile),
	} {
		info, err := os.Stat(dir)
		require.NoError(t, err, dir)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm(), dir)
	}

	for _, file := range []string{
		store.TokenPath(target, qualityoauth.SharedProfile),
		store.IndexPath(),
	} {
		info, err := os.Stat(file)
		require.NoError(t, err, file)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), file)
	}
}

func TestStoreProfilesExcludeTheClientsDirectory(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.NoError(t, store.SaveClient(target, "synq-recon", &qualityoauth.ClientRegistration{ClientID: "c1"}))
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{AccessToken: "a"}))
	require.NoError(t, store.SaveToken(target, "synq-recon", &qualityoauth.Token{AccessToken: "b"}))

	profiles, err := store.Profiles(target)
	require.NoError(t, err)
	require.Equal(t, []string{"shared", "synq-recon"}, profiles, "shared sorts first; clients is not a profile")
}

func TestStoreLoadClientByID(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.NoError(t, store.SaveClient(target, "synq-recon", &qualityoauth.ClientRegistration{ClientID: "recon-1", ClientName: "synq-recon"}))
	require.NoError(t, store.SaveClient(target, "synq-scout", &qualityoauth.ClientRegistration{ClientID: "scout-1", ClientName: "synq-scout"}))

	found, err := store.LoadClientByID(target, "scout-1")
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, "synq-scout", found.ClientName)

	missing, err := store.LoadClientByID(target, "nobody")
	require.NoError(t, err)
	require.Nil(t, missing)

	none, err := store.LoadClientByID(target, "")
	require.NoError(t, err)
	require.Nil(t, none)
}

func TestStoreDeleteProfileKeepsClientRegistrations(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.NoError(t, store.SaveClient(target, "synq-recon", &qualityoauth.ClientRegistration{ClientID: "c1"}))
	require.NoError(t, store.SaveToken(target, "synq-recon", &qualityoauth.Token{AccessToken: "a"}))

	removed, err := store.DeleteProfile(target, "synq-recon")
	require.NoError(t, err)
	require.True(t, removed)

	client, err := store.LoadClient(target, "synq-recon")
	require.NoError(t, err)
	require.NotNil(t, client)

	removed, err = store.DeleteProfile(target, "synq-recon")
	require.NoError(t, err)
	require.False(t, removed)
}

func TestStoreIndexTracksRegionsAndDefaultProfile(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	eu, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	au, err := qualityoauth.TargetForRegion("au")
	require.NoError(t, err)

	require.NoError(t, store.SaveToken(eu, qualityoauth.SharedProfile, &qualityoauth.Token{AccessToken: "a"}))
	require.NoError(t, store.SaveToken(eu, "synq-recon", &qualityoauth.Token{AccessToken: "b"}))
	require.NoError(t, store.SaveToken(au, qualityoauth.SharedProfile, &qualityoauth.Token{AccessToken: "c"}))

	idx, err := store.LoadIndex()
	require.NoError(t, err)
	require.Len(t, idx.Regions, 2)

	euEntry := idx.Regions["developer.synq.io"]
	require.NotNil(t, euEntry)
	require.Equal(t, "eu", euEntry.Region)
	require.Equal(t, "developer.synq.io:443", euEntry.Endpoint)
	require.Equal(t, []string{"shared", "synq-recon"}, euEntry.Profiles)
	require.Equal(t, qualityoauth.SharedProfile, euEntry.DefaultProfile)

	require.NotNil(t, idx.Regions["api.au.synq.io"])

	// The default is explicit and readable back.
	require.NoError(t, store.SetDefaultProfile(eu, "synq-recon"))
	def, err := store.DefaultProfile(eu)
	require.NoError(t, err)
	require.Equal(t, "synq-recon", def)

	// An absent region falls back to the shared profile rather than erroring.
	def, err = store.DefaultProfile(qualityoauth.TargetForEndpoint("self-hosted.example:443"))
	require.NoError(t, err)
	require.Equal(t, qualityoauth.SharedProfile, def)
}

func TestStoreIndexIsRebuiltWhenCorrupt(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(store.Root(), 0o700))
	require.NoError(t, os.WriteFile(store.IndexPath(), []byte("{not json"), 0o600))

	// A corrupt index is surfaced, not silently ignored — it would otherwise
	// hide the fact that the store is in a bad state.
	_, err = store.LoadIndex()
	require.Error(t, err)

	// The credentials themselves are still readable directly, because the
	// index is a convenience and not the source of truth.
	require.NoError(t, os.WriteFile(store.IndexPath(), []byte("{}"), 0o600))
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{AccessToken: "a"}))
	tok, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.Equal(t, "a", tok.AccessToken)
}

func TestStoreEmptyFileIsTreatedAsAbsent(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	path := store.TokenPath(target, qualityoauth.SharedProfile)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	tok, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.Nil(t, tok, "a zero-length file left by an interrupted write is not a credential")
}

func TestValidateProfileRejectsPathEscapesAndReservedNames(t *testing.T) {
	require.NoError(t, qualityoauth.ValidateProfile("shared"))
	require.NoError(t, qualityoauth.ValidateProfile("synq-recon"))
	require.NoError(t, qualityoauth.ValidateProfile("ci_job.2"))

	for _, bad := range []string{"", ".", "..", "../escape", "a/b", `a\b`, "clients"} {
		require.Error(t, qualityoauth.ValidateProfile(bad), "profile %q must be rejected", bad)
	}
}

func TestDefaultStoreHonoursTheHomeOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(qualityoauth.HomeDirEnvVar, dir)

	store, err := qualityoauth.DefaultStore()
	require.NoError(t, err)
	require.Equal(t, dir, store.Root())
}

func TestStatusForTokenWithoutRecordedRegion(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target := qualityoauth.TargetForEndpoint("self-hosted.example:443")
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "a",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}))

	statuses, err := store.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 1)

	st := statuses[0]
	require.Equal(t, "self-hosted.example", st.Host)
	require.Empty(t, st.Region, "a self-hosted endpoint has no named region and must not be given one")
	require.Equal(t, "self-hosted.example:443", st.Endpoint)
	require.False(t, st.Valid)
	require.True(t, st.Expired())
	require.False(t, st.Refreshable)
	require.True(t, st.CoversScopes([]string{"SCOPE_RECON_READ"}),
		"an unrecorded scope set is unknown, not empty")
}

// writeFixture writes a JSON fixture file, shared by the store and e2e tests.
func writeFixture(t *testing.T, path string, body map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(body, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestHasLegacyCredentialIsReadOnly(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.False(t, store.HasLegacyCredential(target))

	writeFixture(t, filepath.Join(store.Root(), "oauth", "token_developer.synq.io.json"), map[string]any{
		"access_token": "legacy",
		"expires_at":   time.Now().Add(time.Hour).Format(time.RFC3339Nano),
	})
	require.True(t, store.HasLegacyCredential(target))

	// Probing must not migrate: a validation path calls this, and a write there
	// would be a surprise.
	tok, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.Nil(t, tok)

	// An extra key covers synqctl, which filed credentials by environment name.
	staging := qualityoauth.TargetForEndpoint("developer.synq.dev:443")
	require.False(t, store.HasLegacyCredential(staging))
	writeFixture(t, filepath.Join(store.Root(), "oauth", "token_staging.json"), map[string]any{
		"access_token": "legacy-staging",
	})
	require.True(t, store.HasLegacyCredential(staging, "staging"))
	require.False(t, store.HasLegacyCredential(staging), "the env-name key is only known to its own CLI")
}

func TestHasStoredCredentialCountsRefreshableAndLegacy(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)
	app := qualityoauth.App{Name: "synq-recon", Scopes: []string{"SCOPE_RECON_READ"}}
	opts := []qualityoauth.Option{qualityoauth.WithStore(store)}

	require.False(t, app.HasStoredCredential(target, nil, opts...))

	// Expired but refreshable counts: the next command renews it silently.
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken:  "a",
		RefreshToken: "r",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}))
	require.True(t, app.HasStoredCredential(target, nil, opts...))

	// Expired with nothing to refresh from does not.
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "a",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}))
	require.False(t, app.HasStoredCredential(target, nil, opts...))

	// A credential for a different region is not this target's.
	us, err := qualityoauth.TargetForRegion("us")
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(us, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "b",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	require.False(t, app.HasStoredCredential(target, nil, opts...))
	require.True(t, app.HasStoredCredential(us, nil, opts...))

	// An internal-flow credential does not satisfy the standard flow.
	internal := target.WithFlow(qualityoauth.FlowInternal)
	require.NoError(t, store.SaveToken(internal, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "c",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	require.False(t, app.HasStoredCredential(target, nil, opts...))
	require.True(t, app.HasStoredCredential(target, nil, append(opts, qualityoauth.WithFlow(qualityoauth.FlowInternal))...))
}
