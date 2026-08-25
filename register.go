package qualityoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RegistrationRequest is the RFC 7591 client metadata a CLI sends to
// /oauth2/register. Beyond the four fields the old copies sent, it carries the
// identity the consent screen and the connected-apps list need in order to
// name the client honestly instead of showing a random id.
type RegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// RegistrationResponse is the subset of the RFC 7591 response we keep.
type RegistrationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	SoftwareID   string   `json:"software_id,omitempty"`
}

const registrationTimeout = 30 * time.Second

// Register performs RFC 7591 dynamic client registration.
func Register(ctx context.Context, client *http.Client, endpoint string, req RegistrationRequest) (*ClientRegistration, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("authorization server advertises no registration_endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient(client).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("registering client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf(
			"registration failed (%d): %s %s",
			resp.StatusCode, errResp.Error, errResp.Description,
		)
	}

	var regResp RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decoding registration response: %w", err)
	}
	if regResp.ClientID == "" {
		return nil, fmt.Errorf("registration response carried no client_id")
	}

	name := regResp.ClientName
	if name == "" {
		name = req.ClientName
	}
	uris := regResp.RedirectURIs
	if len(uris) == 0 {
		uris = req.RedirectURIs
	}
	softwareID := regResp.SoftwareID
	if softwareID == "" {
		softwareID = req.SoftwareID
	}
	return &ClientRegistration{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		ClientName:   name,
		RedirectURIs: uris,
		SoftwareID:   softwareID,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// scopeString joins scopes for the OAuth `scope` parameter.
func scopeString(scopes []string) string { return strings.Join(scopes, " ") }
