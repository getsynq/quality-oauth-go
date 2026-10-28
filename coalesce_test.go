package qualityoauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/getsynq/quality-oauth-go"
	"github.com/stretchr/testify/suite"
)

// fakeCoalesceIssuer is a strict stand-in for the Coalesce (Auth0) issuer a
// deployment advertises as its CLI login: one public native client, registered
// loopback redirects only, S256 PKCE, the advertised audience, single-use codes
// and rotating refresh tokens. Its access tokens carry the Coalesce platform
// claims and an OIDC `scope` claim, which the library must not record as
// Quality scopes.
type fakeCoalesceIssuer struct {
	t      *testing.T
	server *httptest.Server

	mu sync.Mutex

	ClientID     string
	Audience     string
	RedirectURIs []string
	// Accounts and Roles are stamped into every minted token's platform claims.
	Accounts map[string]string
	Roles    []string
	// DefaultOrg is the organization a login without `organization` ends up
	// in, standing in for the issuer's organization prompt.
	DefaultOrg string

	codes         map[string]coalesceCode
	refreshTokens map[string]string
	minted        int

	AuthorizeRequests []url.Values
	TokenGrantTypes   []string
	RefreshClientIDs  []string
}

type coalesceCode struct {
	redirectURI   string
	codeChallenge string
	org           string
}

func newFakeCoalesceIssuer(t *testing.T, redirectURIs []string) *fakeCoalesceIssuer {
	t.Helper()
	s := &fakeCoalesceIssuer{
		t:             t,
		ClientID:      "coalesce-quality-cli",
		Audience:      "coalesce:auth",
		RedirectURIs:  redirectURIs,
		Accounts:      map[string]string{"quality": "coalesce-ws", "catalog": "cat-1"},
		Roles:         []string{"quality:ROLE_ADMIN", "transform:ADMIN"},
		DefaultOrg:    "org_default",
		codes:         map[string]coalesceCode{},
		refreshTokens: map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/token", s.handleToken)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// Issuer is the issuer URL, with the trailing slash Auth0 uses.
func (s *fakeCoalesceIssuer) Issuer() string { return s.server.URL + "/" }

// Offer is the `cli_login` object a deployment advertising this issuer emits.
func (s *fakeCoalesceIssuer) Offer() map[string]any {
	return map[string]any{"issuer": s.Issuer(), "client_id": s.ClientID, "audience": s.Audience}
}

func (s *fakeCoalesceIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"issuer":                           s.Issuer(),
		"authorization_endpoint":           s.server.URL + "/authorize",
		"token_endpoint":                   s.server.URL + "/oauth/token",
		"jwks_uri":                         s.server.URL + "/.well-known/jwks.json",
		"response_types_supported":         []string{"code"},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

func (s *fakeCoalesceIssuer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.AuthorizeRequests = append(s.AuthorizeRequests, q)
	s.mu.Unlock()

	switch {
	case q.Get("client_id") != s.ClientID:
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown client_id "+q.Get("client_id"))
		return
	case !containsString(s.RedirectURIs, q.Get("redirect_uri")):
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "callback URL mismatch")
		return
	case q.Get("response_type") != "code":
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only code is supported")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "S256 PKCE is required")
		return
	case q.Get("audience") != s.Audience:
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "unknown audience "+q.Get("audience"))
		return
	case !containsString(splitScopeParam(q.Get("scope")), "offline_access"):
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "offline_access is required for a refresh token")
		return
	}

	org := q.Get("organization")
	if org == "" {
		org = s.DefaultOrg
	}
	s.mu.Lock()
	code := fmt.Sprintf("coalesce-code-%d", len(s.AuthorizeRequests))
	s.codes[code] = coalesceCode{redirectURI: q.Get("redirect_uri"), codeChallenge: q.Get("code_challenge"), org: org}
	s.mu.Unlock()

	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rq := target.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *fakeCoalesceIssuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.mu.Lock()
	s.TokenGrantTypes = append(s.TokenGrantTypes, r.Form.Get("grant_type"))
	s.mu.Unlock()

	if r.Form.Get("client_id") != s.ClientID {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client "+r.Form.Get("client_id"))
		return
	}

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.mu.Lock()
		issued, ok := s.codes[r.Form.Get("code")]
		delete(s.codes, r.Form.Get("code"))
		s.mu.Unlock()
		if !ok {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown or already-used code")
			return
		}
		if r.Form.Get("redirect_uri") != issued.redirectURI {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the code")
			return
		}
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != issued.codeChallenge {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier does not match the challenge")
			return
		}
		s.issue(w, issued.org)
	case "refresh_token":
		s.mu.Lock()
		s.RefreshClientIDs = append(s.RefreshClientIDs, r.Form.Get("client_id"))
		org, ok := s.refreshTokens[r.Form.Get("refresh_token")]
		// Rotation: a refresh token is good for exactly one exchange.
		delete(s.refreshTokens, r.Form.Get("refresh_token"))
		s.mu.Unlock()
		if !ok {
			writeOAuthError(w, http.StatusForbidden, "invalid_grant", "unknown or rotated refresh token")
			return
		}
		s.issue(w, org)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", r.Form.Get("grant_type"))
	}
}

func (s *fakeCoalesceIssuer) issue(w http.ResponseWriter, org string) {
	s.mu.Lock()
	s.minted++
	serial := s.minted
	refreshToken := fmt.Sprintf("coalesce-refresh-%d", serial)
	s.refreshTokens[refreshToken] = org
	claims := map[string]any{
		"iss":                          s.Issuer(),
		"sub":                          "auth0|user-1",
		"aud":                          []string{s.Audience, s.Issuer() + "userinfo"},
		"org_id":                       org,
		"scope":                        "openid profile email offline_access",
		"https://coalesce.io/accounts": s.Accounts,
		"https://coalesce.io/roles":    s.Roles,
		"exp":                          time.Now().Add(time.Hour).Unix(),
		"jti":                          fmt.Sprintf("coalesce-token-%d", serial),
	}
	s.mu.Unlock()

	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"access_token":  header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".not-a-signature",
		"refresh_token": refreshToken,
		"id_token":      "unused",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "openid profile email offline_access",
	})
}

// set changes the issuer's configuration under its lock, since the server
// reads it from its own goroutines.
func (s *fakeCoalesceIssuer) set(change func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change()
}

func (s *fakeCoalesceIssuer) LastAuthorizeRequest() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.AuthorizeRequests) == 0 {
		s.t.Fatal("no authorize request reached the Coalesce issuer")
	}
	return s.AuthorizeRequests[len(s.AuthorizeRequests)-1]
}

func (s *fakeCoalesceIssuer) GrantTypes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.TokenGrantTypes...)
}

// CoalesceSuite drives the Coalesce login end to end: the deployment's
// discovery advertises a fake Coalesce issuer, and every login, refresh and
// status call runs against the two strict fakes.
type CoalesceSuite struct {
	suite.Suite

	deployment *fakeAuthServer
	issuer     *fakeCoalesceIssuer
	store      *qualityoauth.Store
	target     qualityoauth.Target
	logger     *slog.Logger
}

func TestCoalesceSuite(t *testing.T) {
	suite.Run(t, new(CoalesceSuite))
}

func (s *CoalesceSuite) SetupTest() {
	s.deployment = newFakeAuthServer(s.T())
	s.issuer = newFakeCoalesceIssuer(s.T(), qualityoauth.CallbackRedirectURIs(s.app().CallbackPorts))
	s.deployment.CliLogin = s.issuer.Offer()
	s.store = qualityoauth.NewStore(s.T().TempDir())
	s.target = qualityoauth.TargetForEndpoint(s.deployment.Endpoint())
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.T().Setenv(qualityoauth.AuthProfileEnvVar, "")
}

func (s *CoalesceSuite) app() qualityoauth.App {
	return qualityoauth.App{
		Name:          "synqctl",
		Version:       "1.0.0",
		SoftwareID:    "synqctl",
		Scopes:        []string{"SCOPE_RECON_READ"},
		CallbackPorts: []int{19985, 19986},
	}
}

func (s *CoalesceSuite) opts(extra ...qualityoauth.Option) []qualityoauth.Option {
	base := []qualityoauth.Option{
		qualityoauth.WithStore(s.store),
		qualityoauth.WithLogger(s.logger),
		qualityoauth.WithBrowserOpener(followAuthURL()),
	}
	return append(base, extra...)
}

func (s *CoalesceSuite) login(extra ...qualityoauth.Option) (*qualityoauth.Token, error) {
	ctx := s.T().Context()
	return s.app().Login(ctx, s.target, s.opts(append([]qualityoauth.Option{qualityoauth.WithCoalesceLogin()}, extra...)...)...)
}

func (s *CoalesceSuite) TestLoginRecordsPlatformClaimsAndNoScopes() {
	tok, err := s.login(qualityoauth.WithOrganization("org_acme"))
	s.Require().NoError(err)

	s.Equal(s.issuer.Issuer(), tok.Issuer)
	s.Equal("coalesce-ws", tok.Workspace)
	s.Equal([]string{"ROLE_ADMIN"}, tok.Roles, "only quality: roles are recorded, unprefixed")
	s.Equal("org_acme", tok.Organization)
	s.Equal("auth0|user-1", tok.Subject)
	s.Equal(s.issuer.ClientID, tok.ClientID)
	s.Nil(tok.Scopes, "the OIDC scope claim must never be recorded as Quality scopes")
	s.NotEmpty(tok.RefreshToken)
	s.True(tok.CoalesceLogin())

	authReq := s.issuer.LastAuthorizeRequest()
	s.Equal("coalesce:auth", authReq.Get("audience"))
	s.Equal("org_acme", authReq.Get("organization"))
	s.Equal("openid profile email offline_access", authReq.Get("scope"))
	s.Empty(authReq.Get("flow"))

	// The deployment's own authorization server is used for discovery only.
	s.Zero(s.deployment.RegisterCount(), "the advertised client is never registered")
	s.deployment.mu.Lock()
	s.Empty(s.deployment.AuthorizeRequests)
	s.deployment.mu.Unlock()
	s.Empty(s.deployment.GrantTypes())
	client, err := s.store.LoadClient(s.target, s.app().Name)
	s.Require().NoError(err)
	s.Nil(client, "nothing is cached for a client the deployment owns")

	stored, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Require().NotNil(stored)
	s.Equal(tok.AccessToken, stored.AccessToken)
	s.Equal(tok.Roles, stored.Roles)
	s.Equal(tok.Issuer, stored.Issuer)

	def, ok, err := s.store.DefaultTarget()
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(s.target.Host, def.Host)
}

func (s *CoalesceSuite) TestLoginWithoutOrganizationSendsNone() {
	tok, err := s.login()
	s.Require().NoError(err)

	_, sent := s.issuer.LastAuthorizeRequest()["organization"]
	s.False(sent, "without an organization the issuer prompts for one")
	s.Equal("org_default", tok.Organization)
}

func (s *CoalesceSuite) TestLoginFailsWhenTheDeploymentOffersNoCoalesceLogin() {
	s.deployment.mu.Lock()
	s.deployment.CliLogin = nil
	s.deployment.mu.Unlock()
	opened := false
	_, err := s.app().Login(s.T().Context(), s.target,
		qualityoauth.WithStore(s.store), qualityoauth.WithLogger(s.logger), qualityoauth.WithCoalesceLogin(),
		qualityoauth.WithBrowserOpener(func(string) error { opened = true; return nil }))
	s.Require().ErrorContains(err, "offers no Coalesce login")
	s.False(opened, "the failure comes before a browser opens")
}

func (s *CoalesceSuite) TestLoginFailsWithoutAQualityWorkspace() {
	s.issuer.set(func() { s.issuer.Accounts = map[string]string{"catalog": "cat-1"} })
	_, err := s.login()
	s.Require().ErrorContains(err, "no Coalesce Quality workspace")
	s.assertNothingStored()
}

func (s *CoalesceSuite) TestLoginFailsWithoutAQualityRole() {
	s.issuer.set(func() { s.issuer.Roles = []string{"transform:ADMIN"} })
	_, err := s.login()
	s.Require().ErrorContains(err, "no Coalesce Quality role")
	s.assertNothingStored()
}

func (s *CoalesceSuite) TestOrganizationRequiresCoalesceLogin() {
	_, err := s.app().Login(s.T().Context(), s.target, s.opts(qualityoauth.WithOrganization("org_acme"))...)
	s.Require().ErrorContains(err, "only to a Coalesce login")
}

func (s *CoalesceSuite) TestCredentialCoversTheAppWithoutRecordedScopes() {
	_, err := s.login()
	s.Require().NoError(err)

	cred, err := s.app().Credential(s.T().Context(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Equal(qualityoauth.SourceShared, cred.Source)
	s.Empty(cred.MissingScopes)
}

func (s *CoalesceSuite) TestRefreshGoesToTheCoalesceIssuerAndPersistsTheRotatedToken() {
	first, err := s.login(qualityoauth.WithOrganization("org_acme"))
	s.Require().NoError(err)
	s.expireStoredToken()
	s.issuer.set(func() { s.issuer.Roles = []string{"quality:ROLE_ANALYST"} })

	// A different tool sharing the slot refreshes it as the client that minted it.
	other := qualityoauth.App{Name: "synq-recon", Scopes: []string{"SCOPE_RECON_READ"}}
	cred, err := other.Credential(s.T().Context(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(cred.Token.Valid())
	s.NotEqual(first.AccessToken, cred.Token.AccessToken)
	s.NotEqual(first.RefreshToken, cred.Token.RefreshToken, "the rotated refresh token is the one kept")
	s.Equal([]string{"ROLE_ANALYST"}, cred.Token.Roles, "a role change shows up after refresh")
	s.Equal("org_acme", cred.Token.Organization)
	s.Equal(s.issuer.Issuer(), cred.Token.Issuer)
	s.Nil(cred.Token.Scopes)

	s.Equal([]string{"authorization_code", "refresh_token"}, s.issuer.GrantTypes())
	s.Equal([]string{s.issuer.ClientID}, s.issuer.RefreshClientIDs)
	s.Empty(s.deployment.GrantTypes(), "the deployment's token endpoint never sees a Coalesce refresh token")
	s.Zero(s.deployment.RegisterCount())

	// The rotated token must have been persisted, or this second refresh is
	// rejected by the issuer as a replay.
	s.expireStoredToken()
	again, err := other.Credential(s.T().Context(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.True(again.Token.Valid())
}

func (s *CoalesceSuite) TestRefreshWithoutTheAccountsClaimClearsTheWorkspaceAndRoles() {
	_, err := s.login()
	s.Require().NoError(err)
	s.expireStoredToken()
	s.issuer.set(func() { s.issuer.Accounts, s.issuer.Roles = nil, nil })

	cred, err := s.app().Credential(s.T().Context(), s.target, s.opts()...)
	s.Require().NoError(err)
	s.Empty(cred.Token.Workspace)
	s.Empty(cred.Token.Roles)
	s.Nil(cred.Token.Scopes, "the OIDC scope claim must not be recorded as Quality scopes")
	s.Empty(cred.MissingScopes)
}

func (s *CoalesceSuite) TestQualityLoginAfterCoalesceLoginRequestsOnlyTheAppsScopes() {
	_, err := s.login()
	s.Require().NoError(err)

	tok, err := s.app().Login(s.T().Context(), s.target, s.opts()...)
	s.Require().NoError(err)

	s.Equal("SCOPE_RECON_READ", s.deployment.LastAuthorizeRequest().Scope,
		"OIDC scopes from a Coalesce login must not be unioned into the consent request")
	s.Empty(tok.Issuer)
	s.Empty(tok.Roles)
	s.False(tok.CoalesceLogin())
}

func (s *CoalesceSuite) TestStatusReportsTheCoalesceLogin() {
	_, err := s.login(qualityoauth.WithOrganization("org_acme"))
	s.Require().NoError(err)

	statuses, err := s.app().Status(s.T().Context(), qualityoauth.WithStore(s.store))
	s.Require().NoError(err)
	s.Require().Len(statuses, 1)
	st := statuses[0]
	s.Equal(s.issuer.Issuer(), st.Issuer)
	s.Equal([]string{"ROLE_ADMIN"}, st.Roles)
	s.Equal("org_acme", st.Organization)
	s.Equal("coalesce-ws", st.Workspace)
	s.True(st.CoversScopes([]string{"SCOPE_RECON_READ"}))
}

func (s *CoalesceSuite) TestCoalesceTokenRoundTripsThroughTheStore() {
	tok := &qualityoauth.Token{
		AccessToken:  "a",
		RefreshToken: "r",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		Workspace:    "ws",
		Issuer:       "https://login.example/",
		Roles:        []string{"ROLE_ADMIN"},
		Organization: "org_1",
	}
	s.Require().NoError(s.store.SaveToken(s.target, qualityoauth.SharedProfile, tok))
	loaded, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Equal(tok.Issuer, loaded.Issuer)
	s.Equal(tok.Roles, loaded.Roles)
	s.Equal(tok.Organization, loaded.Organization)
	s.True(loaded.CoalesceLogin())
}

func (s *CoalesceSuite) expireStoredToken() {
	s.T().Helper()
	tok, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Require().NotNil(tok)
	tok.ExpiresAt = time.Now().Add(-time.Minute)
	s.Require().NoError(s.store.SaveToken(s.target, qualityoauth.SharedProfile, tok))
}

func (s *CoalesceSuite) assertNothingStored() {
	s.T().Helper()
	tok, err := s.store.LoadToken(s.target, qualityoauth.SharedProfile)
	s.Require().NoError(err)
	s.Nil(tok, "a rejected login stores nothing")
}
