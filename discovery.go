package qualityoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// discoveryPath is the RFC 8414 authorization server metadata path.
const discoveryPath = "/.well-known/oauth-authorization-server"

// ServerMetadata is the subset of RFC 8414 authorization server metadata the
// CLIs use. Every value comes from the target region's own discovery document —
// the issuer and token endpoint differ per region, so neither is ever
// hardcoded or derived from another region's URL.
type ServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// CliLogin is the Coalesce platform login a deployment offers to CLIs; nil
	// when the deployment offers none.
	CliLogin *CliLogin `json:"cli_login,omitempty"`
}

// CliLogin is the Coalesce (OIDC) login a deployment advertises: the issuer to
// log in against, the public native client to log in as, and the API audience
// the access token must be minted for.
type CliLogin struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Audience string `json:"audience"`
}

// oidcDiscoveryPath is the OpenID Connect discovery path, relative to the issuer.
const oidcDiscoveryPath = "/.well-known/openid-configuration"

// discoveryTimeout bounds the metadata fetch so a login against an unreachable
// region fails with a clear error instead of hanging.
const discoveryTimeout = 15 * time.Second

// Discover fetches a target's authorization server metadata.
func Discover(ctx context.Context, client *http.Client, t Target) (*ServerMetadata, error) {
	return fetchMetadata(ctx, client, t.AuthServerBaseURL()+discoveryPath)
}

// DiscoverOIDC fetches an OpenID provider's metadata from its issuer URL.
func DiscoverOIDC(ctx context.Context, client *http.Client, issuer string) (*ServerMetadata, error) {
	return fetchMetadata(ctx, client, strings.TrimSuffix(issuer, "/")+oidcDiscoveryPath)
}

func fetchMetadata(ctx context.Context, client *http.Client, url string) (*ServerMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient(client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	var meta ServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", url, err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("%s is missing authorization_endpoint or token_endpoint", url)
	}
	return &meta, nil
}

func httpClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}
