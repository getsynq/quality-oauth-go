package qualityoauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// ExpirySkew is subtracted from a token's expiry before it is considered
// usable. Without it a token a second from expiry is handed to a gRPC call that
// then fails with 401 for no visible reason.
const ExpirySkew = 60 * time.Second

// Valid reports whether the token can be used right now, allowing for clock
// skew and request flight time.
func (t *Token) Valid() bool {
	return t.ValidAt(time.Now())
}

// ValidAt reports whether the token is usable at now, skew included.
func (t *Token) ValidAt(now time.Time) bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	if t.ExpiresAt.IsZero() {
		// A token with no recorded expiry is treated as usable — the server is
		// the authority, and refusing it would break a hand-written slot.
		return true
	}
	return now.Add(ExpirySkew).Before(t.ExpiresAt)
}

// Expired reports whether the token has passed its expiry outright, as opposed
// to merely being inside the skew window. The distinction matters in CLI
// output: "expires in 30s, renewing" reads very differently from "expired".
func (t *Token) Expired() bool {
	return t != nil && !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// Refreshable reports whether an expired token can be renewed without a browser.
func (t *Token) Refreshable() bool {
	return t != nil && t.RefreshToken != ""
}

// Refresh exchanges a refresh token for a new access token.
func Refresh(
	ctx context.Context,
	httpCli *http.Client,
	meta *ServerMetadata,
	clientID, clientSecret, refreshToken string,
) (*FlowResult, error) {
	cfg := oauthConfig(meta, clientID, clientSecret, "", nil)

	if httpCli != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpCli)
	}
	// An already-expired Expiry is what makes the token source do the refresh
	// rather than hand the stale token straight back.
	stale := &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-time.Hour)}
	fresh, err := cfg.TokenSource(ctx, stale).Token()
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}

	return &FlowResult{
		AccessToken:   fresh.AccessToken,
		RefreshToken:  fresh.RefreshToken,
		TokenType:     fresh.TokenType,
		ExpiresAt:     fresh.Expiry,
		GrantedScopes: grantedScopes(fresh, nil),
	}, nil
}

// tokenClaims is the subset of the minted JWT's claims worth recording next to
// the token: they let `auth status` report the workspace offline, which is what
// makes a silently-flipped default workspace visible before a command runs
// against the wrong tenant.
type tokenClaims struct {
	Subject   string   `json:"sub"`
	Workspace string   `json:"workspace"`
	Scopes    []string `json:"scopes"`
	Scope     string   `json:"scope"`
}

// applyClaims records the identity carried by the access token on the stored
// token. The JWT is NOT verified here — the CLI is not the audience and holds
// no keys. These values are display and cache-selection metadata only; every
// authorization decision is the server's.
func (t *Token) applyClaims() {
	claims, err := parseUnverifiedClaims(t.AccessToken)
	if err != nil || claims == nil {
		return
	}
	if claims.Workspace != "" {
		t.Workspace = claims.Workspace
	}
	if claims.Subject != "" {
		t.Subject = claims.Subject
	}
	// Prefer the token's own scope claim over the requested set: it is what
	// the server actually granted.
	scopes := claims.Scopes
	if len(scopes) == 0 && claims.Scope != "" {
		scopes = splitScopes(claims.Scope)
	}
	if len(scopes) > 0 {
		t.Scopes = dedupeScopes(scopes)
	}
}

func parseUnverifiedClaims(accessToken string) (*tokenClaims, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding token payload: %w", err)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing token claims: %w", err)
	}
	return &claims, nil
}
