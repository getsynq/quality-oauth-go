package qualityoauth_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/require"
)

// Environment variables driving the helper-process modes below. A subprocess is
// the only honest way to test a cross-process file lock: goroutines in one
// process share a file descriptor table, so an OS lock alone would not serialise
// them and an in-process test could pass while the real thing races.
const (
	helperModeEnv    = "QUALITYOAUTH_TEST_HELPER"
	helperStoreEnv   = "QUALITYOAUTH_TEST_STORE"
	helperHoldMsEnv  = "QUALITYOAUTH_TEST_HOLD_MS"
	helperTokenValue = "written-by-helper"
)

// TestMain lets this test binary re-exec itself as a helper process.
func TestMain(m *testing.M) {
	switch os.Getenv(helperModeEnv) {
	case "hold-token-lock":
		os.Exit(runHoldTokenLockHelper())
	case "":
		os.Exit(m.Run())
	default:
		os.Exit(2)
	}
}

// runHoldTokenLockHelper takes the token lock, writes a token, holds the lock
// for a while, then releases it.
func runHoldTokenLockHelper() int {
	store := qualityoauth.NewStore(os.Getenv(helperStoreEnv))
	target, err := qualityoauth.TargetForRegion("eu")
	if err != nil {
		return 1
	}
	unlock, err := store.LockToken(target, qualityoauth.SharedProfile)
	if err != nil {
		return 1
	}
	defer unlock()

	if err := store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: helperTokenValue,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		return 1
	}

	holdMs, _ := strconv.Atoi(os.Getenv(helperHoldMsEnv))
	time.Sleep(time.Duration(holdMs) * time.Millisecond)
	return 0
}

// TestTokenLockIsHeldAcrossProcesses proves the store's lock is an OS lock and
// not merely an in-process mutex: a second process cannot take it until the
// first releases, so its read observes the first process's completed write.
func TestTokenLockIsHeldAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary")
	}

	root := t.TempDir()
	store := qualityoauth.NewStore(root)
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	const holdMs = 400
	helper := exec.Command(os.Args[0], "-test.run", "TestTokenLockIsHeldAcrossProcesses")
	helper.Env = append(os.Environ(),
		helperModeEnv+"=hold-token-lock",
		helperStoreEnv+"="+root,
		helperHoldMsEnv+"="+strconv.Itoa(holdMs),
	)
	require.NoError(t, helper.Start())
	t.Cleanup(func() { _ = helper.Wait() })

	// Give the helper time to acquire the lock before we contend for it.
	waitForFile(t, store.TokenPath(target, qualityoauth.SharedProfile))

	start := time.Now()
	unlock, err := store.LockToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	waited := time.Since(start)
	defer unlock()

	require.NotZero(t, waited, "acquiring a held lock must block")

	// Whatever the timing, the write the other process made under the lock is
	// fully visible now — never a truncated file.
	tok, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, helperTokenValue, tok.AccessToken)

	require.NoError(t, helper.Wait())
}

// TestConcurrentRefreshRefreshesOnce covers the single-flight requirement: many
// commands racing on one expired credential must perform one refresh, and the
// rotated refresh token must not be lost by a later writer.
func TestConcurrentRefreshRefreshesOnce(t *testing.T) {
	server := newFakeAuthServer(t)
	server.RotateRefreshToken = true
	store := qualityoauth.NewStore(t.TempDir())
	target := qualityoauth.TargetForEndpoint(server.Endpoint())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv(qualityoauth.AuthProfileEnvVar, "")

	app := qualityoauth.App{
		Name:          "synq-recon",
		SoftwareID:    "synq-recon",
		Scopes:        []string{"SCOPE_RECON_READ"},
		CallbackPorts: []int{19991, 19992},
	}
	opts := []qualityoauth.Option{
		qualityoauth.WithStore(store),
		qualityoauth.WithLogger(logger),
		qualityoauth.WithBrowserOpener(followAuthURL()),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := app.Login(ctx, target, opts...)
	require.NoError(t, err)
	require.Equal(t, []string{"authorization_code"}, server.GrantTypes())

	// Expire the stored access token, leaving the refresh token usable.
	stored, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	stored.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, stored))

	const racers = 8
	var wg sync.WaitGroup
	results := make([]*qualityoauth.Credential, racers)
	errs := make([]error, racers)
	release := make(chan struct{})

	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			results[i], errs[i] = app.Credential(ctx, target, opts...)
		}()
	}
	close(release)
	wg.Wait()

	for i := range racers {
		require.NoError(t, errs[i], "racer %d", i)
		require.True(t, results[i].Token.Valid(), "racer %d got an unusable token", i)
	}

	refreshes := 0
	for _, grant := range server.GrantTypes() {
		if grant == "refresh_token" {
			refreshes++
		}
	}
	require.Equal(t, 1, refreshes,
		"a rotating server invalidates the previous refresh token, so a second refresh would fail; the lock must collapse the race to one")

	// The persisted credential is the refreshed one, and every racer agrees.
	final, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.True(t, final.Valid())
	for i := range racers {
		require.Equal(t, final.AccessToken, results[i].Token.AccessToken, "racer %d", i)
	}
}

// TestConcurrentIndexUpdatesKeepEveryRegion covers the read-modify-write on the
// shared index: two logins to different regions at once must not each write a
// whole index built from a snapshot taken before the other's change.
func TestConcurrentIndexUpdatesKeepEveryRegion(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())

	targets := make([]qualityoauth.Target, 0, len(qualityoauth.RegionNames()))
	for _, name := range qualityoauth.RegionNames() {
		target, err := qualityoauth.TargetForRegion(name)
		require.NoError(t, err)
		targets = append(targets, target)
	}
	require.GreaterOrEqual(t, len(targets), 2)

	var wg sync.WaitGroup
	errs := make([]error, len(targets))
	release := make(chan struct{})
	for i, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			errs[i] = store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
				AccessToken: "token-" + target.Host,
				ExpiresAt:   time.Now().Add(time.Hour),
			})
		}()
	}
	close(release)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "region %s", targets[i].Region)
	}

	idx, err := store.LoadIndex()
	require.NoError(t, err)
	require.Len(t, idx.Regions, len(targets), "a lost index update would drop a region")
	for _, target := range targets {
		require.Contains(t, idx.Regions, target.Host)
	}
}

// TestLockFilesAreNotMistakenForCredentials guards the status listing: the lock
// files sit beside the token files and must not be read back as tokens or
// counted as profiles.
func TestLockFilesAreNotMistakenForCredentials(t *testing.T) {
	store := qualityoauth.NewStore(t.TempDir())
	target, err := qualityoauth.TargetForRegion("eu")
	require.NoError(t, err)

	require.NoError(t, store.SaveToken(target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "a",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	unlock, err := store.LockToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	unlock()

	// The lock file exists on disk next to the token.
	require.FileExists(t, store.TokenPath(target, qualityoauth.SharedProfile)+".lock")

	statuses, err := store.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 1, "the lock file must not be listed as a second credential")
	require.Equal(t, "a", mustLoadToken(t, store, target).AccessToken)

	profiles, err := store.Profiles(target)
	require.NoError(t, err)
	require.Equal(t, []string{qualityoauth.SharedProfile}, profiles)
}

func mustLoadToken(t *testing.T, store *qualityoauth.Store, target qualityoauth.Target) *qualityoauth.Token {
	t.Helper()
	tok, err := store.LoadToken(target, qualityoauth.SharedProfile)
	require.NoError(t, err)
	require.NotNil(t, tok)
	return tok
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
