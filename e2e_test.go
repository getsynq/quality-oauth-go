package qualityoauth_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/suite"
)

// E2ESuite drives the whole login flow — discovery, RFC 7591 registration,
// PKCE authorization, loopback callback, code exchange, refresh, status and
// logout — against a strict fake authorization server, with the credential
// store in a temp directory. Nothing is stubbed inside the library.
type E2ESuite struct {
	suite.Suite

	server *fakeAuthServer
	store  *qualityoauth.Store
	target qualityoauth.Target
	logger *slog.Logger
}

func TestE2ESuite(t *testing.T) {
	suite.Run(t, new(E2ESuite))
}

func (s *E2ESuite) SetupTest() {
	s.server = newFakeAuthServer(s.T())
	s.store = qualityoauth.NewStore(s.T().TempDir())
	s.target = qualityoauth.TargetForEndpoint(s.server.Endpoint())
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	// A stray SYNQ_AUTH_PROFILE in the developer's shell would silently
	// redirect every credential in these tests.
	s.T().Setenv(qualityoauth.AuthProfileEnvVar, "")
}

// reconApp and scoutApp stand in for two of our CLIs sharing one machine.
func (s *E2ESuite) reconApp() qualityoauth.App {
	return qualityoauth.App{
		Name:          "synq-recon",
		Version:       "1.2.3",
		SoftwareID:    "synq-recon",
		Scopes:        []string{"SCOPE_RECON_READ", "SCOPE_RECON_EDIT", "SCOPE_INGEST_RECON"},
		CallbackPorts: []int{19981, 19982},
		ClientURI:     "https://coalesce.io",
	}
}

func (s *E2ESuite) scoutApp() qualityoauth.App {
	return qualityoauth.App{
		Name:          "synq-scout",
		Version:       "4.5.6",
		SoftwareID:    "synq-scout",
		Scopes:        []string{"SCOPE_MCP_READ"},
		CallbackPorts: []int{19983, 19984},
	}
}

// opts are the options every call in these tests shares: the temp store, a
// silent logger, and a browser that is really an HTTP client.
func (s *E2ESuite) opts(extra ...qualityoauth.Option) []qualityoauth.Option {
	base := []qualityoauth.Option{
		qualityoauth.WithStore(s.store),
		qualityoauth.WithLogger(s.logger),
		qualityoauth.WithBrowserOpener(s.browserOpener()),
	}
	return append(base, extra...)
}

// browserOpener stands in for the user's browser.
func (s *E2ESuite) browserOpener() func(string) error { return followAuthURL() }

func (s *E2ESuite) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.T().Cleanup(cancel)
	return ctx
}

func (s *E2ESuite) TestLoginStoresSharedCredential() {
	app := s.reconApp()

	tok, err := app.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Require().NotNil(tok)

	s.NotEmpty(tok.AccessToken)
	s.NotEmpty(tok.RefreshToken)
	s.Equal("test-workspace", tok.Workspace, "the workspace is recorded so status works offline")
	s.ElementsMatch(app.Scopes, tok.Scopes)
	s.True(tok.Valid())

	// The credential lands in the shared slot, so the whole toolchain reuses it.
	stored, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Require().NotNil(stored)
	s.Equal(tok.AccessToken, stored.AccessToken)
	s.Equal(s.target.Endpoint, stored.Endpoint)

	// Refresh tokens are long-lived bearer credentials; the file must not be
	// group- or world-readable.
	info, err := os.Stat(s.store.TokenPath(s.target, qualityoauth.SharedProfile))
	s.Require().NoError(err)
	s.Equal(os.FileMode(0o600), info.Mode().Perm())

	// The index records the slot so `auth status` can enumerate regions.
	idx, err := s.store.LoadIndex()
	s.Require().NoError(err)
	entry := idx.Regions[s.target.Host]
	s.Require().NotNil(entry)
	s.Contains(entry.Profiles, qualityoauth.SharedProfile)
}

func (s *E2ESuite) TestLoginRequestsOnlyTheAppsDeclaredScopes() {
	app := s.reconApp()

	_, err := app.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	authReq := s.server.LastAuthorizeRequest()
	s.Equal("SCOPE_INGEST_RECON SCOPE_RECON_EDIT SCOPE_RECON_READ", authReq.Scope,
		"the scope parameter must carry exactly what the tool declared, not the user's whole envelope")
	s.Empty(authReq.Flow)

	s.Require().Equal(1, s.server.RegisterCount())
	reg := s.server.RegisterRequests[0]
	s.Equal("synq-recon", reg.ClientName)
	s.Equal("synq-recon", reg.SoftwareID)
	s.Equal("1.2.3", reg.SoftwareVersion)
	s.Equal("native", reg.ApplicationType)
	s.Equal("https://coalesce.io", reg.ClientURI)
	s.Equal("SCOPE_INGEST_RECON SCOPE_RECON_EDIT SCOPE_RECON_READ", reg.Scope)
	s.Equal([]string{"http://127.0.0.1:19981/callback", "http://127.0.0.1:19982/callback"}, reg.RedirectURIs)
}

// TestTwoToolsKeepDistinctClientIdentities is the mutual-clobber regression:
// recon and scout logging in on one machine must register as themselves, and
// the second login must not leave the first tool unable to refresh.
func (s *E2ESuite) TestTwoToolsKeepDistinctClientIdentities() {
	recon, scout := s.reconApp(), s.scoutApp()

	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	_, err = scout.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Equal(2, s.server.RegisterCount(), "each tool registers as itself")

	reconClient, err := s.store.LoadClient(s.target, "synq-recon")
	s.Require().NoError(err)
	s.Require().NotNil(reconClient)
	scoutClient, err := s.store.LoadClient(s.target, "synq-scout")
	s.Require().NoError(err)
	s.Require().NotNil(scoutClient)

	s.Equal("synq-recon", reconClient.ClientName)
	s.Equal("synq-scout", scoutClient.ClientName)
	s.NotEqual(reconClient.ClientID, scoutClient.ClientID,
		"a shared client id is what made the whole toolchain show as one anonymous app")

	// Both tools resolve a usable credential afterwards.
	reconCred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(reconCred.Token.Valid())
	scoutCred, err := scout.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(scoutCred.Token.Valid())

	// The shared slot was last written by scout, so it records scout's client —
	// and recon refreshing it must present that client, not its own.
	s.Equal(scoutClient.ClientID, reconCred.Token.ClientID)
}

// TestSharedCredentialRefreshesUnderTheMintingClient proves the above matters:
// a refresh presenting the wrong client_id is rejected by the server.
func (s *E2ESuite) TestSharedCredentialRefreshesUnderTheMintingClient() {
	s.server.RotateRefreshToken = true
	recon, scout := s.reconApp(), s.scoutApp()

	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	// scout takes over the shared slot, so the stored token belongs to scout's
	// client while recon is the tool that will refresh it.
	_, err = scout.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.expireStoredToken(qualityoauth.SharedProfile)

	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(cred.Token.Valid())
	s.Contains(s.server.GrantTypes(), "refresh_token")

	scoutClient, err := s.store.LoadClient(s.target, "synq-scout")
	s.Require().NoError(err)
	s.Equal(scoutClient.ClientID, cred.Token.ClientID)
}

func (s *E2ESuite) TestIsolatedLoginDoesNotTouchTheSharedSlot() {
	recon := s.reconApp()

	shared, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	isolated, err := recon.Login(s.ctx(), s.target, s.opts(qualityoauth.WithIsolated())...)
	s.Require().NoError(err)
	s.NotEqual(shared.AccessToken, isolated.AccessToken)

	stillShared, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(shared.AccessToken, stillShared.AccessToken, "the shared slot is untouched by an isolated login")

	perApp, err := s.store.LoadToken(s.target, "synq-recon")
	s.Require().NoError(err)
	s.Require().NotNil(perApp)
	s.Equal(isolated.AccessToken, perApp.AccessToken)

	// Resolution prefers the app's own slot over the shared one.
	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Equal(qualityoauth.SourcePerApp, cred.Source)
	s.Equal(isolated.AccessToken, cred.Token.AccessToken)

	// Only one registration: the client identity is per app, not per slot.
	s.Equal(1, s.server.RegisterCount())
}

// TestRegionsDoNotClobberEachOther covers the EU/US requirement: two targets
// hold two credentials at once and neither token can leak into the other.
func (s *E2ESuite) TestRegionsDoNotClobberEachOther() {
	other := newFakeAuthServer(s.T())
	other.Workspace = "other-region-workspace"

	// Two loopback names give two distinct host partitions, as two regions do.
	targetA := qualityoauth.TargetForEndpoint(s.server.EndpointVia("127.0.0.1"))
	targetB := qualityoauth.TargetForEndpoint(other.EndpointVia("localhost"))
	s.Require().NotEqual(targetA.Host, targetB.Host)

	recon := s.reconApp()
	tokA, err := recon.Login(s.ctx(), targetA, s.opts()...)
	s.Require().NoError(err)
	tokB, err := recon.Login(s.ctx(), targetB, s.opts()...)
	s.Require().NoError(err)

	s.NotEqual(tokA.AccessToken, tokB.AccessToken)
	s.Equal("test-workspace", tokA.Workspace)
	s.Equal("other-region-workspace", tokB.Workspace)

	credA, err := recon.Credential(s.ctx(), targetA, s.opts()...)
	s.Require().NoError(err)
	credB, err := recon.Credential(s.ctx(), targetB, s.opts()...)
	s.Require().NoError(err)
	s.Equal(tokA.AccessToken, credA.Token.AccessToken)
	s.Equal(tokB.AccessToken, credB.Token.AccessToken)

	// Logging out of one region leaves the other logged in.
	removed, err := recon.Logout(s.ctx(), targetA, s.opts()...)
	s.Require().NoError(err)
	s.True(removed)
	_, err = recon.Credential(s.ctx(), targetA, s.opts()...)
	s.ErrorIs(err, qualityoauth.ErrNoCredentials)
	_, err = recon.Credential(s.ctx(), targetB, s.opts()...)
	s.NoError(err)
}

func (s *E2ESuite) TestLoginRecordsTheDeploymentLaterCommandsResolveTo() {
	other := newFakeAuthServer(s.T())
	targetA := qualityoauth.TargetForEndpoint(s.server.EndpointVia("127.0.0.1"))
	targetB := qualityoauth.TargetForEndpoint(other.EndpointVia("localhost"))

	recon := s.reconApp()
	_, _, err := recon.DefaultTarget(s.opts()...)
	s.Require().NoError(err)

	_, err = recon.Login(s.ctx(), targetA, s.opts()...)
	s.Require().NoError(err)
	got, ok, err := recon.DefaultTarget(s.opts()...)
	s.Require().NoError(err)
	s.Require().True(ok)
	s.Equal(targetA.Host, got.Host)

	// The last login wins: switching deployment is switching deployment.
	_, err = recon.Login(s.ctx(), targetB, s.opts()...)
	s.Require().NoError(err)
	got, ok, err = recon.DefaultTarget(s.opts()...)
	s.Require().NoError(err)
	s.Require().True(ok)
	s.Equal(targetB.Host, got.Host)

	// Another tool sharing the store sees the same choice.
	got, ok, err = s.scoutApp().DefaultTarget(s.opts()...)
	s.Require().NoError(err)
	s.Require().True(ok)
	s.Equal(targetB.Host, got.Host)

	// Logging out of the remembered deployment forgets it rather than leaving
	// every later command resolving to a region with no credential.
	_, err = recon.Logout(s.ctx(), targetB, s.opts()...)
	s.Require().NoError(err)
	_, ok, err = recon.DefaultTarget(s.opts()...)
	s.Require().NoError(err)
	s.False(ok)
}

func (s *E2ESuite) TestStatusReportsEveryRegionOffline() {
	other := newFakeAuthServer(s.T())
	other.Workspace = "other-region-workspace"
	targetA := qualityoauth.TargetForEndpoint(s.server.EndpointVia("127.0.0.1"))
	targetB := qualityoauth.TargetForEndpoint(other.EndpointVia("localhost"))

	recon, scout := s.reconApp(), s.scoutApp()
	_, err := recon.Login(s.ctx(), targetA, s.opts()...)
	s.Require().NoError(err)
	_, err = recon.Login(s.ctx(), targetA, s.opts(qualityoauth.WithIsolated())...)
	s.Require().NoError(err)
	_, err = scout.Login(s.ctx(), targetB, s.opts()...)
	s.Require().NoError(err)

	// Both servers go away: status must need no network at all.
	s.server.Close()
	other.Close()

	statuses, err := recon.Status(s.ctx(), s.opts()...)
	s.Require().NoError(err)
	s.Require().Len(statuses, 3)

	byKey := map[string]qualityoauth.Status{}
	for _, st := range statuses {
		byKey[st.Host+"/"+st.Profile] = st
	}

	sharedA := byKey[targetA.Host+"/"+qualityoauth.SharedProfile]
	s.Equal("test-workspace", sharedA.Workspace)
	s.True(sharedA.Valid)
	s.True(sharedA.Refreshable)
	s.ElementsMatch(recon.Scopes, sharedA.Scopes)
	s.True(sharedA.CoversScopes(recon.Scopes))
	// The shared profile is the default, so this is the line most users see. It
	// used to be blank: the client was looked up by profile, and registrations
	// are keyed by app name.
	s.Equal("synq-recon", sharedA.ClientName, "the shared credential must name the client that minted it")
	s.NotEmpty(sharedA.ClientID)

	perAppA := byKey[targetA.Host+"/synq-recon"]
	s.Equal("synq-recon", perAppA.Profile)
	s.Equal("synq-recon", perAppA.ClientName)
	s.NotEmpty(perAppA.ClientID)

	sharedB := byKey[targetB.Host+"/"+qualityoauth.SharedProfile]
	s.Equal("other-region-workspace", sharedB.Workspace)
	s.ElementsMatch(scout.Scopes, sharedB.Scopes)
}

// TestIncrementalConsentUnionsScopes covers the case the issue calls out: the
// shared token exists but lacks a scope the tool needs, so the next login asks
// for granted ∪ needed instead of narrowing the existing grant.
func (s *E2ESuite) TestIncrementalConsentUnionsScopes() {
	scout, recon := s.scoutApp(), s.reconApp()

	_, err := scout.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	// scout's token does not cover recon's needs.
	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.ElementsMatch(recon.Scopes, cred.MissingScopes)

	_, err = recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Equal(
		"SCOPE_INGEST_RECON SCOPE_MCP_READ SCOPE_RECON_EDIT SCOPE_RECON_READ",
		s.server.LastAuthorizeRequest().Scope,
		"re-consent must broaden the shared grant, not replace it with a narrower one",
	)

	// Both tools are now covered by the one shared credential.
	reconCred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Empty(reconCred.MissingScopes)
	scoutCred, err := scout.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Empty(scoutCred.MissingScopes)
}

// TestAdoptedEnvelopeIsNotCarriedIntoTheNextConsent is the counterpart to
// incremental consent: a credential adopted from the pre-consolidation store
// carries the caller's whole role-derived envelope in its claims, because the
// flow that minted it requested no scopes. Unioning that in would put every one
// of those permissions on the consent screen of every tool, forever.
func (s *E2ESuite) TestAdoptedEnvelopeIsNotCarriedIntoTheNextConsent() {
	envelope := []string{
		"SCOPE_MCP_READ",
		"SCOPE_RECON_READ",
		"SCOPE_USER_EDIT",
		"SCOPE_POLICIES_EDIT",
		"SCOPE_EXTENSIONS_MANAGE",
	}
	s.server.GrantScopes = envelope

	// Mint a real grant, then file it in the legacy shape and adopt it, which is
	// how a machine that logged in before the consolidation arrives here.
	recon := s.reconApp()
	seeded, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	seededClient, err := s.store.LoadClient(s.target, recon.Name)
	s.Require().NoError(err)

	legacyStore := qualityoauth.NewStore(s.T().TempDir())
	s.writeLegacyCredential(legacyStore, s.target.Host, seeded, seededClient)
	opts := []qualityoauth.Option{
		qualityoauth.WithStore(legacyStore),
		qualityoauth.WithLogger(s.logger),
		qualityoauth.WithBrowserOpener(s.browserOpener()),
	}

	scout := s.scoutApp()
	_, err = scout.MigrateLegacyCredentials(s.target, nil, opts...)
	s.Require().NoError(err)

	adopted, err := legacyStore.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Require().NotNil(adopted)
	s.ElementsMatch(envelope, adopted.Scopes, "the claims are still reported as what the token carries")
	s.Equal(qualityoauth.ScopeSourceClaims, adopted.ScopeSource)
	s.Empty(adopted.ConsentedScopes(), "nothing here was ever put to a consent screen")

	// The login asks for scout's own needs, not the adopted envelope.
	s.server.GrantScopes = nil
	_, err = scout.Login(s.ctx(), s.target, opts...)
	s.Require().NoError(err)
	s.Equal("SCOPE_MCP_READ", s.server.LastAuthorizeRequest().Scope,
		"an adopted envelope must not be re-requested on behalf of a tool that never needed it")

	// What that consent did grant is a real grant, so the next tool broadens it.
	consented, err := legacyStore.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(qualityoauth.ScopeSourceConsent, consented.ScopeSource)
	_, err = recon.Login(s.ctx(), s.target, opts...)
	s.Require().NoError(err)
	s.Equal(
		"SCOPE_INGEST_RECON SCOPE_MCP_READ SCOPE_RECON_EDIT SCOPE_RECON_READ",
		s.server.LastAuthorizeRequest().Scope,
		"the union still applies once a human has approved the set being broadened",
	)
}

// TestNewlyDeclaredScopeIsRequestedWithoutReregistering covers a tool that grows
// a scope after the user has already logged in — a scope nobody declined, that
// simply did not exist when the credential and the client registration were
// written. Two things have to hold: the missing scope is noticed against the
// app's current declared set rather than anything recorded at login time, and the
// stale `scope` on the cached client registration does not cap what the next
// authorize request may ask for.
func (s *E2ESuite) TestNewlyDeclaredScopeIsRequestedWithoutReregistering() {
	before := s.scoutApp()
	_, err := before.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Require().Len(s.server.RegisterRequests, 1)
	registered := s.server.RegisterRequests[0]
	s.Equal("SCOPE_MCP_READ", registered.Scope)

	// The next release of the same tool needs one more permission.
	after := s.scoutApp()
	after.Scopes = append(after.Scopes, "SCOPE_ISSUES_EDIT")

	cred, err := after.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Equal([]string{"SCOPE_ISSUES_EDIT"}, cred.MissingScopes,
		"a scope added to the declared set must surface without the user doing anything")

	_, err = after.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Equal("SCOPE_ISSUES_EDIT SCOPE_MCP_READ", s.server.LastAuthorizeRequest().Scope)
	s.Equal(registered.ClientID, s.server.LastAuthorizeRequest().ClientID,
		"the same client asks for more; a new scope is not a reason to register again")
	s.Len(s.server.RegisterRequests, 1, "re-registering would leave a client row per release")

	broadened, err := after.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Empty(broadened.MissingScopes)
}

// TestRefreshKeepsScopeProvenance pins that renewing an adopted credential does
// not launder its envelope into something the next login will re-request.
func (s *E2ESuite) TestRefreshKeepsScopeProvenance() {
	s.server.GrantScopes = []string{"SCOPE_MCP_READ", "SCOPE_USER_EDIT"}
	recon := s.reconApp()
	seeded, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	seededClient, err := s.store.LoadClient(s.target, recon.Name)
	s.Require().NoError(err)

	legacyStore := qualityoauth.NewStore(s.T().TempDir())
	s.writeLegacyCredential(legacyStore, s.target.Host, seeded, seededClient)
	opts := []qualityoauth.Option{
		qualityoauth.WithStore(legacyStore),
		qualityoauth.WithLogger(s.logger),
		qualityoauth.WithBrowserOpener(s.browserOpener()),
	}

	scout := s.scoutApp()
	_, err = scout.MigrateLegacyCredentials(s.target, nil, opts...)
	s.Require().NoError(err)

	adopted, err := legacyStore.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	adopted.ExpiresAt = time.Now().Add(-time.Minute)
	s.Require().NoError(legacyStore.SaveToken(s.target, qualityoauth.SharedProfile, adopted))

	cred, err := scout.Credential(s.ctx(), s.target, opts...)
	s.Require().NoError(err)
	s.True(cred.Token.Valid(), "the adopted credential refreshes without a browser")
	s.Equal(qualityoauth.ScopeSourceClaims, cred.Token.ScopeSource)
	s.Empty(cred.Token.ConsentedScopes())
}

func (s *E2ESuite) TestNarrowerGrantIsReportedNotHidden() {
	// The user holds only one of the scopes recon asked for.
	s.server.GrantScopes = []string{"SCOPE_RECON_READ"}
	recon := s.reconApp()

	tok, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Equal([]string{"SCOPE_RECON_READ"}, tok.Scopes)

	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.ElementsMatch([]string{"SCOPE_RECON_EDIT", "SCOPE_INGEST_RECON"}, cred.MissingScopes,
		"a silently under-scoped credential surfaces as a 403 much later; report it here")
}

func (s *E2ESuite) TestExpiredTokenRefreshesTransparently() {
	s.server.RotateRefreshToken = true
	recon := s.reconApp()

	original, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.expireStoredToken(qualityoauth.SharedProfile)

	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.NotEqual(original.AccessToken, cred.Token.AccessToken)
	s.True(cred.Token.Valid())
	s.Contains(s.server.GrantTypes(), "refresh_token")

	// The renewed token is written back, so the next invocation does not
	// refresh again.
	stored, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(cred.Token.AccessToken, stored.AccessToken)
	s.NotEqual(original.RefreshToken, stored.RefreshToken, "a rotated refresh token must be persisted")
}

// TestTokenInsideSkewWindowIsRefreshed is the clock-skew regression: a token
// seconds from expiry used to be handed out and then 401.
func (s *E2ESuite) TestTokenInsideSkewWindowIsRefreshed() {
	recon := s.reconApp()
	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	// Still in the future, but inside the skew window.
	s.setStoredExpiry(qualityoauth.SharedProfile, time.Now().Add(qualityoauth.ExpirySkew/2))

	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Contains(s.server.GrantTypes(), "refresh_token")
	s.True(cred.Token.ExpiresAt.After(time.Now().Add(qualityoauth.ExpirySkew)))
}

func (s *E2ESuite) TestUnrefreshablePerAppSlotFallsBackToShared() {
	recon := s.reconApp()

	sharedTok, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	// A per-app slot that is expired and cannot be renewed must not mask a
	// perfectly good shared credential.
	s.Require().NoError(s.store.SaveToken(s.target, "synq-recon", &qualityoauth.Token{
		AccessToken: "stale-access-token",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}))

	cred, err := recon.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Equal(qualityoauth.SourceShared, cred.Source)
	s.Equal(sharedTok.AccessToken, cred.Token.AccessToken)
}

func (s *E2ESuite) TestExplicitProfileDoesNotFallBack() {
	recon := s.reconApp()
	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	// An explicitly requested profile that is empty is an error, not a silent
	// downgrade to the shared credential — the caller asked for isolation.
	_, err = recon.Credential(s.ctx(), s.target, s.opts(qualityoauth.WithProfile("ci"))...)
	s.ErrorIs(err, qualityoauth.ErrNoCredentials)
	s.ErrorContains(err, `profile "ci"`)
}

func (s *E2ESuite) TestInternalFlowUsesItsOwnTokenSlot() {
	admin := qualityoauth.App{
		Name:          "synqctl",
		SoftwareID:    "synqctl",
		CallbackPorts: []int{19985, 19986},
	}

	public, err := admin.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	internal, err := admin.Login(s.ctx(), s.target, s.opts(qualityoauth.WithFlow(qualityoauth.FlowInternal))...)
	s.Require().NoError(err)
	s.NotEqual(public.AccessToken, internal.AccessToken)

	s.Equal(qualityoauth.FlowInternal, s.server.LastAuthorizeRequest().Flow,
		"the flow flavour must reach the authorization server as a query parameter")

	// Neither slot overwrote the other.
	storedPublic, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(public.AccessToken, storedPublic.AccessToken)

	internalTarget := s.target.WithFlow(qualityoauth.FlowInternal)
	storedInternal, err := s.store.LoadToken(internalTarget, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(internal.AccessToken, storedInternal.AccessToken)

	// And status lists both, distinguished by flow.
	statuses, err := admin.Status(s.ctx(), s.opts()...)
	s.Require().NoError(err)
	s.Require().Len(statuses, 2)
	flows := []string{statuses[0].Flow, statuses[1].Flow}
	s.ElementsMatch([]string{"", qualityoauth.FlowInternal}, flows)
}

func (s *E2ESuite) TestFirstPartyClientSkipsDynamicRegistration() {
	app := s.reconApp()
	app.FirstPartyClientID = "synq-recon"
	s.server.SeedFirstPartyClient("synq-recon", qualityoauth.CallbackRedirectURIs(app.CallbackPorts))

	tok, err := app.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Equal(0, s.server.RegisterCount(), "a seeded first-party id must not mint a client row per machine")
	s.Equal("synq-recon", tok.ClientID)
	s.Equal("synq-recon", s.server.LastAuthorizeRequest().ClientID)

	// No client registration file is written either.
	_, err = os.Stat(s.store.ClientPath(s.target, app.Name))
	s.True(os.IsNotExist(err))

	// Refresh works against the seeded id.
	s.expireStoredToken(qualityoauth.SharedProfile)
	cred, err := app.Credential(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(cred.Token.Valid())
}

func (s *E2ESuite) TestReloginReusesTheCachedRegistration() {
	recon := s.reconApp()

	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	_, err = recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Equal(1, s.server.RegisterCount(), "re-login must not grow the clients table")
}

func (s *E2ESuite) TestStateMismatchIsRejected() {
	s.server.CallbackState = "attacker-supplied-state"
	recon := s.reconApp()

	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().Error(err)
	s.ErrorContains(err, "state mismatch")

	stored, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Nil(stored, "a rejected callback must not leave a credential behind")
}

func (s *E2ESuite) TestLogoutKeepsTheClientRegistration() {
	recon := s.reconApp()
	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	removed, err := recon.Logout(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(removed)

	_, err = recon.Credential(s.ctx(), s.target, s.opts()...)
	s.ErrorIs(err, qualityoauth.ErrNoCredentials)

	client, err := s.store.LoadClient(s.target, recon.Name)
	s.Require().NoError(err)
	s.Require().NotNil(client, "dropping the registration would mint a new client row on the next login")

	// Logging back in reuses it.
	_, err = recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Equal(1, s.server.RegisterCount())

	// A second logout reports that there was nothing to remove.
	removed, err = recon.Logout(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(removed)
	removed, err = recon.Logout(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.False(removed)
}

// TestLegacyCredentialIsMigratedInPlace covers "nobody has to re-authenticate
// because of the store move": the flat file is read, the new layout is written,
// and the old file is left alone.
func (s *E2ESuite) TestLegacyCredentialIsMigratedInPlace() {
	recon := s.reconApp()

	// Stand up a real grant on the server, then write it out in the legacy
	// shape so the migrated credential is genuinely refreshable.
	seeded, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	seededClient, err := s.store.LoadClient(s.target, recon.Name)
	s.Require().NoError(err)

	legacyStore := qualityoauth.NewStore(s.T().TempDir())
	s.writeLegacyCredential(legacyStore, s.target.Host, seeded, seededClient)
	legacyTokenFile := filepath.Join(legacyStore.Root(), "oauth", "token_"+s.target.Host+".json")

	opts := []qualityoauth.Option{
		qualityoauth.WithStore(legacyStore),
		qualityoauth.WithLogger(s.logger),
		qualityoauth.WithBrowserOpener(s.browserOpener()),
	}

	result, err := recon.MigrateLegacyCredentials(s.target, nil, opts...)
	s.Require().NoError(err)
	s.True(result.TokenMigrated)
	s.True(result.ClientMigrated)
	s.Equal(s.target.Host, result.SourceKey)

	migrated, err := legacyStore.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Require().NotNil(migrated)
	s.Equal(seeded.AccessToken, migrated.AccessToken)
	s.Equal(seeded.RefreshToken, migrated.RefreshToken)
	s.Equal("test-workspace", migrated.Workspace, "the workspace is recovered from the token's own claims")
	s.Equal(seededClient.ClientID, migrated.ClientID)

	// The legacy file is still there: an older binary on this machine keeps
	// working, and a half-finished migration cannot lose a refresh token.
	s.FileExists(legacyTokenFile)

	// The migrated credential is usable and refreshable.
	cred, err := recon.Credential(s.ctx(), s.target, opts...)
	s.Require().NoError(err)
	s.Equal(seeded.AccessToken, cred.Token.AccessToken)

	s.Require().NoError(legacyStore.SaveToken(s.target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken:  migrated.AccessToken,
		RefreshToken: migrated.RefreshToken,
		ClientID:     migrated.ClientID,
		ExpiresAt:    time.Now().Add(-time.Minute),
	}))
	refreshed, err := recon.Credential(s.ctx(), s.target, opts...)
	s.Require().NoError(err)
	s.True(refreshed.Token.Valid())

	// Re-running the migration is a no-op and never clobbers the newer token.
	again, err := recon.MigrateLegacyCredentials(s.target, nil, opts...)
	s.Require().NoError(err)
	s.False(again.Migrated())
	current, err := legacyStore.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(refreshed.Token.AccessToken, current.AccessToken)
}

func (s *E2ESuite) TestServerWithoutRefreshTokenStillLogsIn() {
	s.server.SuppressRefreshToken = true
	recon := s.reconApp()

	tok, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Empty(tok.RefreshToken)
	s.False(tok.Refreshable())

	// And once it expires there is nothing to fall back to, so the caller is
	// told to log in rather than being handed a dead token.
	s.expireStoredToken(qualityoauth.SharedProfile)
	_, err = recon.Credential(s.ctx(), s.target, s.opts()...)
	s.ErrorIs(err, qualityoauth.ErrNoCredentials)
}

// expireStoredToken rewrites a stored token so its access token has expired,
// leaving the refresh token intact.
func (s *E2ESuite) expireStoredToken(profile string) {
	s.setStoredExpiry(profile, time.Now().Add(-time.Minute))
}

func (s *E2ESuite) setStoredExpiry(profile string, expiry time.Time) {
	s.T().Helper()
	tok, err := s.store.LoadToken(s.target, profile)
	s.Require().NoError(err)
	s.Require().NotNil(tok)
	tok.ExpiresAt = expiry
	s.Require().NoError(s.store.SaveToken(s.target, profile, tok))
}

// writeLegacyCredential lays down the flat ~/.synq/oauth/{client,token}_<key>.json
// pair the pre-consolidation CLIs wrote.
func (s *E2ESuite) writeLegacyCredential(
	store *qualityoauth.Store,
	key string,
	tok *qualityoauth.Token,
	client *qualityoauth.ClientRegistration,
) {
	s.T().Helper()
	dir := filepath.Join(store.Root(), "oauth")
	s.Require().NoError(os.MkdirAll(dir, 0o700))

	writeFixture(s.T(), filepath.Join(dir, "token_"+key+".json"), map[string]any{
		"access_token":  tok.AccessToken,
		"refresh_token": tok.RefreshToken,
		"token_type":    "Bearer",
		"expires_at":    tok.ExpiresAt.Format(time.RFC3339Nano),
	})
	writeFixture(s.T(), filepath.Join(dir, "client_"+key+".json"), map[string]any{
		"client_id":     client.ClientID,
		"client_name":   client.ClientName,
		"redirect_uris": client.RedirectURIs,
		"created_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// TestStatusNamesTheClientForEveryProfile is the regression for `auth status`
// showing no client at all on the default path. The client identity has to come
// from the token, which records what minted it: registrations are filed by app
// name, so looking one up by profile finds nothing for the shared profile and only
// coincidentally works when a per-app profile is named after its app.
func (s *E2ESuite) TestStatusNamesTheClientForEveryProfile() {
	recon, scout := s.reconApp(), s.scoutApp()

	_, err := recon.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)
	_, err = recon.Login(s.ctx(), s.target, s.opts(qualityoauth.WithIsolated())...)
	s.Require().NoError(err)
	// A profile named after nothing in particular, as --auth-profile allows.
	_, err = scout.Login(s.ctx(), s.target, s.opts(qualityoauth.WithProfile("ci"))...)
	s.Require().NoError(err)

	statuses, err := recon.Status(s.ctx(), s.opts()...)
	s.Require().NoError(err)
	s.Require().Len(statuses, 3)

	wantClient := map[string]string{
		qualityoauth.SharedProfile: "synq-recon",
		"synq-recon":               "synq-recon",
		"ci":                       "synq-scout",
	}
	for _, st := range statuses {
		s.NotEmpty(st.ClientID, "profile %q must report the client id that minted its token", st.Profile)
		s.Equal(wantClient[st.Profile], st.ClientName, "profile %q", st.Profile)
	}
}

// TestStatusNamesASeededFirstPartyClient covers the other half: a first-party app
// writes no registration file at all, so anything reading a registration from disk
// reports no client once FirstPartyClientID is flipped on.
func (s *E2ESuite) TestStatusNamesASeededFirstPartyClient() {
	app := s.reconApp()
	app.FirstPartyClientID = "synq-recon"
	s.server.SeedFirstPartyClient("synq-recon", qualityoauth.CallbackRedirectURIs(app.CallbackPorts))

	_, err := app.Login(s.ctx(), s.target, s.opts()...)
	s.Require().NoError(err)

	// Nothing on disk to read a name from.
	_, statErr := os.Stat(s.store.ClientPath(s.target, app.Name))
	s.Require().True(os.IsNotExist(statErr))

	statuses, err := app.Status(s.ctx(), s.opts()...)
	s.Require().NoError(err)
	s.Require().Len(statuses, 1)
	s.Equal("synq-recon", statuses[0].ClientID)
	s.Equal("synq-recon", statuses[0].ClientName)
}

// TestStatusOmitsAnUnknownClientRatherThanGuessing keeps a hand-written or very old
// token slot honest: with no recorded client there is nothing to report, and the
// CLI renderers drop the line rather than invent one.
func (s *E2ESuite) TestStatusOmitsAnUnknownClientRatherThanGuessing() {
	s.Require().NoError(s.store.SaveToken(s.target, qualityoauth.SharedProfile, &qualityoauth.Token{
		AccessToken: "hand-written",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	statuses, err := s.reconApp().Status(s.ctx(), s.opts()...)
	s.Require().NoError(err)
	s.Require().Len(statuses, 1)
	s.Empty(statuses[0].ClientID)
	s.Empty(statuses[0].ClientName)
}
