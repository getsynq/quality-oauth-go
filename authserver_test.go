package qualityoauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeAuthServer is a minimal but strict OAuth 2.0 authorization server: it
// enforces PKCE, registered redirect URIs, single-use codes and client
// identity, so a test failure means the client got the protocol wrong rather
// than the stub being permissive. It records what the client sent so tests can
// assert on the requested scope, the flow flavour and the registered metadata.
type fakeAuthServer struct {
	t      *testing.T
	server *httptest.Server

	mu sync.Mutex

	// registrations are the dynamically registered clients, by client_id.
	registrations map[string]qualityRegistration
	// firstParty are pre-seeded client ids that need no registration, standing
	// in for the ids a migration seeds in each region.
	firstParty map[string][]string
	// codes are live authorization codes, by code.
	codes map[string]*issuedCode
	// refreshTokens maps a live refresh token to the grant it belongs to.
	refreshTokens map[string]*grant

	// Recorded requests, for assertions.
	RegisterRequests  []qualityRegistration
	AuthorizeRequests []authorizeRequest
	TokenGrantTypes   []string

	// Workspace is stamped into every minted token's claims.
	Workspace string
	// GrantScopes, when non-nil, overrides what the server grants regardless of
	// what was requested — the "user cannot grant everything asked for" case.
	GrantScopes []string
	// RotateRefreshToken makes each refresh return a new refresh token.
	RotateRefreshToken bool
	// AccessTokenTTL is how long minted access tokens last.
	AccessTokenTTL time.Duration
	// CallbackState overrides the state returned to the redirect URI, to
	// exercise the CSRF check.
	CallbackState string
	// SuppressRefreshToken drops the refresh token from the token response.
	SuppressRefreshToken bool
	// CliLogin, when set, is advertised as the deployment's Coalesce login.
	CliLogin map[string]any

	// minted counts issued access tokens so each one is distinguishable; two
	// mints a second apart would otherwise produce byte-identical JWTs and
	// hide a "the token was never actually replaced" bug.
	minted int
}

type qualityRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	PolicyURI               string   `json:"policy_uri"`
	TosURI                  string   `json:"tos_uri"`
	SoftwareID              string   `json:"software_id"`
	SoftwareVersion         string   `json:"software_version"`
	Scope                   string   `json:"scope"`
}

type authorizeRequest struct {
	ClientID    string
	RedirectURI string
	Scope       string
	Flow        string
	State       string
}

type issuedCode struct {
	clientID      string
	redirectURI   string
	codeChallenge string
	scopes        []string
}

// grant is what a refresh token can be exchanged for.
type grant struct {
	clientID string
	scopes   []string
}

func newFakeAuthServer(t *testing.T) *fakeAuthServer {
	t.Helper()
	s := &fakeAuthServer{
		t:              t,
		registrations:  map[string]qualityRegistration{},
		firstParty:     map[string][]string{},
		codes:          map[string]*issuedCode{},
		refreshTokens:  map[string]*grant{},
		Workspace:      "test-workspace",
		AccessTokenTTL: time.Hour,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleMetadata)
	mux.HandleFunc("/oauth2/register", s.handleRegister)
	mux.HandleFunc("/oauth2/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth2/token", s.handleToken)
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// Endpoint is the host:port a Target should be built from.
func (s *fakeAuthServer) Endpoint() string {
	return strings.TrimPrefix(s.server.URL, "http://")
}

// EndpointVia returns the endpoint reached through an alternate loopback name,
// so two fake servers occupy two distinct store partitions the way two regions
// would.
func (s *fakeAuthServer) EndpointVia(host string) string {
	_, port, ok := strings.Cut(s.Endpoint(), ":")
	require.True(s.t, ok, "endpoint %q has no port", s.Endpoint())
	return host + ":" + port
}

// SeedFirstPartyClient registers a fixed client id with no dynamic
// registration, as a region's seeding migration does.
func (s *fakeAuthServer) SeedFirstPartyClient(clientID string, redirectURIs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.firstParty[clientID] = redirectURIs
}

// Close shuts the server down early, so a test can prove a code path performs
// no network I/O.
func (s *fakeAuthServer) Close() { s.server.Close() }

func (s *fakeAuthServer) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	base := s.server.URL
	body := map[string]any{
		"issuer":                                base + "/",
		"authorization_endpoint":                base + "/oauth2/authorize",
		"token_endpoint":                        base + "/oauth2/token",
		"registration_endpoint":                 base + "/oauth2/register",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	s.mu.Lock()
	if s.CliLogin != nil {
		body["cli_login"] = s.CliLogin
	}
	s.mu.Unlock()
	writeJSONResponse(w, http.StatusOK, body)
}

func (s *fakeAuthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req qualityRegistration
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	if req.ClientName == "" || len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name and redirect_uris are required")
		return
	}
	if req.TokenEndpointAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only token_endpoint_auth_method=none is supported")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	req.ClientID = fmt.Sprintf("dyn-%s-%d", req.ClientName, len(s.registrations)+1)
	s.registrations[req.ClientID] = req
	s.RegisterRequests = append(s.RegisterRequests, req)

	writeJSONResponse(w, http.StatusCreated, map[string]any{
		"client_id":                  req.ClientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                req.GrantTypes,
		"token_endpoint_auth_method": "none",
		"software_id":                req.SoftwareID,
	})
}

func (s *fakeAuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	challenge := q.Get("code_challenge")

	s.mu.Lock()
	s.AuthorizeRequests = append(s.AuthorizeRequests, authorizeRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       q.Get("scope"),
		Flow:        q.Get("flow"),
		State:       state,
	})
	registered, isKnown := s.knownRedirectURIsLocked(clientID)
	s.mu.Unlock()

	if !isKnown {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown client_id "+clientID)
		return
	}
	if !containsString(registered, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered: "+redirectURI)
		return
	}
	if q.Get("response_type") != "code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only code is supported")
		return
	}
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "S256 PKCE is required")
		return
	}

	granted := splitScopeParam(q.Get("scope"))
	if s.GrantScopes != nil {
		granted = s.GrantScopes
	}

	s.mu.Lock()
	code := fmt.Sprintf("code-%d", len(s.codes)+1)
	s.codes[code] = &issuedCode{
		clientID:      clientID,
		redirectURI:   redirectURI,
		codeChallenge: challenge,
		scopes:        granted,
	}
	returnedState := state
	if s.CallbackState != "" {
		returnedState = s.CallbackState
	}
	s.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rq := target.Query()
	rq.Set("code", code)
	rq.Set("state", returnedState)
	target.RawQuery = rq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *fakeAuthServer) knownRedirectURIsLocked(clientID string) ([]string, bool) {
	if uris, ok := s.firstParty[clientID]; ok {
		return uris, true
	}
	if reg, ok := s.registrations[clientID]; ok {
		return reg.RedirectURIs, true
	}
	return nil, false
}

func (s *fakeAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	grantType := r.Form.Get("grant_type")

	s.mu.Lock()
	s.TokenGrantTypes = append(s.TokenGrantTypes, grantType)
	s.mu.Unlock()

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshGrant(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", grantType)
	}
}

func (s *fakeAuthServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	verifier := r.Form.Get("code_verifier")
	clientID := r.Form.Get("client_id")

	s.mu.Lock()
	issued, ok := s.codes[code]
	if ok {
		// Authorization codes are single-use; leaving one live would let a
		// broken client replay it and still pass the test.
		delete(s.codes, code)
	}
	s.mu.Unlock()

	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown or already-used code")
		return
	}
	if clientID != issued.clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client_id does not match the code")
		return
	}
	if r.Form.Get("redirect_uri") != issued.redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the code")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != issued.codeChallenge {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verifier does not match the challenge")
		return
	}

	s.issueTokens(w, issued.clientID, issued.scopes)
}

func (s *fakeAuthServer) handleRefreshGrant(w http.ResponseWriter, r *http.Request) {
	presented := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")

	s.mu.Lock()
	g, ok := s.refreshTokens[presented]
	if ok && s.RotateRefreshToken {
		delete(s.refreshTokens, presented)
	}
	s.mu.Unlock()

	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if clientID != "" && clientID != g.clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "refresh token belongs to another client")
		return
	}
	s.issueTokens(w, g.clientID, g.scopes)
}

func (s *fakeAuthServer) issueTokens(w http.ResponseWriter, clientID string, scopes []string) {
	s.mu.Lock()
	s.minted++
	serial := s.minted
	// The serial, not the map size, names the refresh token: rotation deletes
	// the previous entry, so a size-derived name would reuse the old string and
	// a "the rotated token was never persisted" bug would pass unnoticed.
	refreshToken := fmt.Sprintf("refresh-%s-%d", clientID, serial)
	s.refreshTokens[refreshToken] = &grant{clientID: clientID, scopes: scopes}
	workspace := s.Workspace
	ttl := s.AccessTokenTTL
	suppress := s.SuppressRefreshToken
	s.mu.Unlock()

	body := map[string]any{
		"access_token": fakeJWT(workspace, clientID, scopes, time.Now().Add(ttl), serial),
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
		"scope":        strings.Join(scopes, " "),
	}
	if !suppress {
		body["refresh_token"] = refreshToken
	}
	writeJSONResponse(w, http.StatusOK, body)
}

// RegisteredClientIDs returns the ids of every dynamically registered client.
func (s *fakeAuthServer) RegisteredClientIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.registrations))
	for id := range s.registrations {
		ids = append(ids, id)
	}
	return ids
}

// LastAuthorizeRequest is the most recent /oauth2/authorize the client made.
func (s *fakeAuthServer) LastAuthorizeRequest() authorizeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(s.t, s.AuthorizeRequests, "no authorize request was made")
	return s.AuthorizeRequests[len(s.AuthorizeRequests)-1]
}

// RegisterCount is how many dynamic registrations the client performed.
func (s *fakeAuthServer) RegisterCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.RegisterRequests)
}

// GrantTypes is every grant_type the token endpoint saw, in order.
func (s *fakeAuthServer) GrantTypes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.TokenGrantTypes...)
}

// fakeJWT builds an unsigned JWT-shaped access token. The library reads these
// claims without verifying them (it is not the audience and holds no keys), so
// an unsigned token is the honest fixture.
func fakeJWT(workspace, subject string, scopes []string, expiry time.Time, serial int) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{
		"sub":       subject,
		"workspace": workspace,
		"scopes":    scopes,
		"exp":       expiry.Unix(),
		"iat":       time.Now().Unix(),
		"jti":       fmt.Sprintf("token-%d", serial),
	})
	if err != nil {
		panic(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".not-a-signature"
}

func writeJSONResponse(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSONResponse(w, status, map[string]any{"error": code, "error_description": description})
}

// followAuthURL stands in for the user's browser: it fetches the authorization
// URL and follows the redirect back to the CLI's loopback callback, which is
// exactly what a real browser does.
func followAuthURL() func(string) error {
	return func(authURL string) error {
		go func() {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(authURL)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
		return nil
	}
}

func splitScopeParam(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Fields(raw)
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
