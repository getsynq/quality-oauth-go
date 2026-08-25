package qualityoauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

// FlowInternal targets the deployment's admin authorize branch: it is gated on the
// internal-flow role allow-list and mints the caller's full role-derived scope
// envelope rather than a consented scope subset. It shares this package's flow
// implementation and gets its own token slot in the store.
const FlowInternal = "internal"

// DefaultCallbackPorts are the loopback ports the callback server tries, in
// order. They are registered as redirect URIs so any of them is accepted.
var DefaultCallbackPorts = []int{19876, 19877, 19878}

// callbackPath is the loopback redirect path.
const callbackPath = "/callback"

// authorizationTimeout bounds how long a login waits for the user to finish in
// the browser before giving up and releasing the callback port.
const authorizationTimeout = 10 * time.Minute

// FlowRequest is one authorization-code-with-PKCE exchange.
type FlowRequest struct {
	Metadata     *ServerMetadata
	ClientID     string
	ClientSecret string
	// Listener is the already-bound loopback listener the callback is served
	// on, and RedirectURI is the URI it answers. The caller binds it (see
	// ListenOnCallbackPort) so the port cannot be lost to another process
	// between choosing it and serving on it.
	Listener    net.Listener
	RedirectURI string
	// Scopes is sent as the `scope` parameter so the consent screen can
	// pre-check exactly what this tool needs. Sending nothing is what made
	// every CLI token carry the user's whole scope envelope.
	Scopes []string
	// Flow is forwarded to the authorization server as the `flow` query parameter.
	Flow string
	// OpenBrowser launches the browser; nil uses OpenBrowser.
	OpenBrowser func(string) error
	// Logger receives progress; nil uses slog.Default().
	Logger *slog.Logger
	// HTTPClient is used for the token exchange. nil uses http.DefaultClient.
	HTTPClient *http.Client
}

// FlowResult is the token set an authorization-code exchange produced.
type FlowResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	// GrantedScopes is what the server says it actually granted, which can be
	// narrower than what was requested — the user may not hold every scope.
	GrantedScopes []string
}

// CallbackRedirectURIs are the loopback URIs to register for a set of ports.
func CallbackRedirectURIs(ports []int) []string {
	uris := make([]string, 0, len(ports))
	for _, port := range ports {
		uris = append(uris, fmt.Sprintf("http://127.0.0.1:%d%s", port, callbackPath))
	}
	return uris
}

// ListenOnCallbackPort binds the first free callback port and returns the
// listener together with its redirect URI. Binding up front (rather than
// probing and re-binding) closes the window where another process could take
// the port between the check and the listen.
func ListenOnCallbackPort(ports []int) (net.Listener, string, error) {
	for _, port := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		return l, fmt.Sprintf("http://%s%s", addr, callbackPath), nil
	}
	return nil, "", fmt.Errorf("could not bind any callback port (%v); close whatever is using them and retry", ports)
}

// RunAuthorizationCodeFlow runs the PKCE authorization code flow: it serves the
// loopback callback on req.Listener, opens the browser, and exchanges the
// returned code. The listener is consumed — it is closed on return.
func RunAuthorizationCodeFlow(ctx context.Context, req FlowRequest) (*FlowResult, error) {
	if req.Listener == nil {
		return nil, fmt.Errorf("no callback listener provided")
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE challenge: %w", err)
	}
	state, err := randomString(24)
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	cfg := oauthConfig(req.Metadata, req.ClientID, req.ClientSecret, req.RedirectURI, req.Scopes)

	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if req.Flow != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("flow", req.Flow))
	}
	authURL := cfg.AuthCodeURL(state, authOpts...)

	redirect, err := url.Parse(req.RedirectURI)
	if err != nil {
		_ = req.Listener.Close()
		return nil, fmt.Errorf("parsing redirect URI %q: %w", req.RedirectURI, err)
	}
	path := redirect.Path
	if path == "" {
		path = callbackPath
	}

	log := logger(req.Logger)
	// The URL is logged before the browser is launched: it is the user's only
	// way forward on a headless machine or when the opener fails.
	log.InfoContext(ctx, "Opening a browser to authorize; visit this URL if it does not open", "url", authURL)
	open := req.OpenBrowser
	if open == nil {
		open = OpenBrowser
	}
	if err := open(authURL); err != nil {
		log.WarnContext(ctx, "Could not open a browser; open the logged URL manually", "error", err)
	}

	code, err := awaitCallback(ctx, req.Listener, path, state, log)
	if err != nil {
		return nil, err
	}

	log.DebugContext(ctx, "Exchanging the authorization code for a token")
	exchangeCtx := ctx
	if req.HTTPClient != nil {
		exchangeCtx = context.WithValue(ctx, oauth2.HTTPClient, req.HTTPClient)
	}
	token, err := cfg.Exchange(exchangeCtx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code: %w", err)
	}

	return &FlowResult{
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		TokenType:     token.TokenType,
		ExpiresAt:     token.Expiry,
		GrantedScopes: grantedScopes(token, req.Scopes),
	}, nil
}

// awaitCallback serves the loopback redirect until the browser hits it, then
// shuts the server down and returns the authorization code.
func awaitCallback(ctx context.Context, listener net.Listener, path, state string, log *slog.Logger) (string, error) {
	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		code, err := readCallback(r, state)
		respondToCallback(w, err)
		select {
		case resultCh <- result{code: code, err: err}:
		default:
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	timeout := time.NewTimer(authorizationTimeout)
	defer timeout.Stop()

	log.InfoContext(ctx, "Waiting for the authorization callback", "redirect", listener.Addr().String())
	select {
	case res := <-resultCh:
		return res.code, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timeout.C:
		return "", fmt.Errorf("timed out after %s waiting for the browser to complete authorization", authorizationTimeout)
	}
}

func readCallback(r *http.Request, state string) (string, error) {
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		return "", fmt.Errorf("authorization denied: %s %s", errParam, q.Get("error_description"))
	}
	// Constant-time compare: the state value is the CSRF defence for the
	// loopback redirect, which any local process can reach.
	got, want := q.Get("state"), state
	if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return "", fmt.Errorf("state mismatch on the authorization callback")
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("authorization callback carried no code")
	}
	return code, nil
}

func respondToCallback(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Connection", "close")
	body := "<h2>Authorization successful</h2><p>You can close this window and return to your terminal.</p>"
	if err != nil {
		body = fmt.Sprintf("<h2>Authorization failed</h2><p>%s</p><p>You can close this window.</p>", html.EscapeString(err.Error()))
	}
	_, _ = fmt.Fprintf(w, "<!doctype html><html><body style=\"font-family:system-ui;margin:3rem\">%s</body></html>", body)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func oauthConfig(meta *ServerMetadata, clientID, clientSecret, redirectURI string, scopes []string) *oauth2.Config {
	// A public client sends client_id in the body; a confidential one uses
	// Basic auth. Guessing wrong makes the token endpoint reject the exchange.
	authStyle := oauth2.AuthStyleInParams
	if clientSecret != "" {
		authStyle = oauth2.AuthStyleInHeader
	}
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   meta.AuthorizationEndpoint,
			TokenURL:  meta.TokenEndpoint,
			AuthStyle: authStyle,
		},
		RedirectURL: redirectURI,
		Scopes:      scopes,
	}
}

// grantedScopes prefers the server's own answer (RFC 6749 `scope` on the token
// response) and falls back to what was requested when the server stays silent.
func grantedScopes(token *oauth2.Token, requested []string) []string {
	if raw, ok := token.Extra("scope").(string); ok && raw != "" {
		return splitScopes(raw)
	}
	return requested
}

func generatePKCE() (verifier, challenge string, err error) {
	verifier, err = randomString(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// logger falls back to slog.Default(), which every CLI in this repo configures
// at startup.
func logger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}
