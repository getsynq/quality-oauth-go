package qualityoauth

import (
	"fmt"
	"os"
)

// Environment variables every CLI honours. These paths are the CI story and
// deliberately take precedence over anything in the credential store: a
// pipeline that exports client credentials must never silently pick up a
// developer's browser login.
//
// The names are the brand-neutral ones. Every one of them has a SYNQ_-prefixed
// predecessor that is still read (see deprecatedEnvVars) — they are in customer
// CI and .env files, so they are aliased rather than retired — but the promoted
// name is what documentation, help text and new configuration should use.
// Always read them through Getenv, never os.Getenv, or the alias is silently
// dropped for that one setting.
const (
	ClientIDEnvVar     = "QUALITY_CLIENT_ID"
	ClientSecretEnvVar = "QUALITY_CLIENT_SECRET"
	TokenEnvVar        = "QUALITY_TOKEN"
	EndpointEnvVar     = "QUALITY_API_ENDPOINT"
	RegionEnvVar       = "QUALITY_REGION"
)

// deprecatedEnvVars maps each promoted name to the name it replaced. A promoted
// name that is set wins; an empty one falls through, so exporting the new name
// with an empty value does not mask an existing SYNQ_ setting.
var deprecatedEnvVars = map[string]string{
	ClientIDEnvVar:     "SYNQ_CLIENT_ID",
	ClientSecretEnvVar: "SYNQ_CLIENT_SECRET",
	TokenEnvVar:        "SYNQ_TOKEN",
	EndpointEnvVar:     "SYNQ_API_ENDPOINT",
	RegionEnvVar:       "SYNQ_REGION",
	AuthProfileEnvVar:  "SYNQ_AUTH_PROFILE",
	HomeDirEnvVar:      "SYNQ_HOME",
}

// Getenv reads one of the settings above, preferring the promoted name and
// falling back to the SYNQ_-prefixed one it replaced.
func Getenv(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if legacy, ok := deprecatedEnvVars[name]; ok {
		return os.Getenv(legacy)
	}
	return ""
}

// DeprecatedEnvVar returns the SYNQ_-prefixed name a promoted setting replaced,
// for help text and deprecation notices.
func DeprecatedEnvVar(name string) (string, bool) {
	legacy, ok := deprecatedEnvVars[name]
	return legacy, ok
}

// EnvCredentialKind is which environment-provided credential was found.
type EnvCredentialKind string

const (
	// EnvCredentialNone means the environment carries no credential and the
	// store should be consulted.
	EnvCredentialNone EnvCredentialKind = ""
	// EnvCredentialClient is an OAuth2 client-credentials pair.
	EnvCredentialClient EnvCredentialKind = "client_credentials"
	// EnvCredentialToken is a pre-issued API token sent as a bearer.
	EnvCredentialToken EnvCredentialKind = "token"
)

// EnvCredential is a credential taken from the environment.
type EnvCredential struct {
	Kind         EnvCredentialKind
	ClientID     string
	ClientSecret string
	Token        string
}

// Found reports whether the environment carried a credential.
func (c EnvCredential) Found() bool { return c.Kind != EnvCredentialNone }

// EnvCredentialFromEnv reads the environment credential, if any. Client
// credentials win over a static token because they are the narrower, renewable
// form; a partially-set pair (id without secret) is not a credential and is
// ignored rather than half-applied.
func EnvCredentialFromEnv() EnvCredential {
	id, secret := Getenv(ClientIDEnvVar), Getenv(ClientSecretEnvVar)
	if id != "" && secret != "" {
		return EnvCredential{Kind: EnvCredentialClient, ClientID: id, ClientSecret: secret}
	}
	if token := Getenv(TokenEnvVar); token != "" {
		return EnvCredential{Kind: EnvCredentialToken, Token: token}
	}
	return EnvCredential{}
}

// Sources is everywhere a CLI can learn which deployment to talk to. It is the
// one place that ordering lives, so every CLI answers `--region us` the same
// way and a new tier is added once rather than four times.
type Sources struct {
	// EndpointFlag is --endpoint (or a deprecated alias such as --synq-endpoint).
	EndpointFlag string
	// RegionFlag is --region.
	RegionFlag string
	// ConfiguredEndpoint is an endpoint from non-flag configuration a CLI
	// already honours — a suite's `synq.endpoint`, a .env file. It deliberately
	// loses to --region rather than conflicting with it: a .env in the working
	// directory is not something the user typed.
	ConfiguredEndpoint string
	// Store supplies the remembered deployment; nil uses DefaultStore.
	Store *Store
}

// Resolve picks the deployment, in strict precedence order:
//
//  1. an endpoint flag (the escape hatch for staging and self-hosted);
//  2. a region flag;
//  3. a configured endpoint (suite YAML, a .env file);
//  4. QUALITY_API_ENDPOINT;
//  5. QUALITY_REGION;
//  6. the deployment of the last successful login;
//  7. the default region.
//
// Within each tier an endpoint beats a region, and only a contradiction between
// two *flags* is an error: a shell exporting both QUALITY_REGION and a staging
// QUALITY_API_ENDPOINT is a normal setup, and the endpoint is unambiguously the
// more specific of the two.
//
// The remembered deployment sits below every explicit source and above the
// hard-coded default, so it only ever changes an invocation that would
// otherwise have silently assumed the default region.
func (s Sources) Resolve() (Target, error) {
	if s.EndpointFlag != "" || s.RegionFlag != "" {
		return ResolveTarget(s.RegionFlag, s.EndpointFlag)
	}
	if s.ConfiguredEndpoint != "" {
		return validatedEndpoint(s.ConfiguredEndpoint, "configured endpoint")
	}
	if endpoint := Getenv(EndpointEnvVar); endpoint != "" {
		return validatedEndpoint(endpoint, EndpointEnvVar)
	}
	if region := Getenv(RegionEnvVar); region != "" {
		return TargetForRegion(region)
	}
	if target, ok, err := s.rememberedTarget(); err != nil {
		return Target{}, err
	} else if ok {
		return target, nil
	}
	return TargetForRegion(DefaultRegion)
}

// rememberedTarget reads the deployment of the last successful login. A store
// that cannot be read is not an error here: it is the weakest source, so a
// broken or unreadable credential index falls through to the default region
// rather than failing every command.
func (s Sources) rememberedTarget() (Target, bool, error) {
	store := s.Store
	if store == nil {
		var err error
		if store, err = DefaultStore(); err != nil {
			return Target{}, false, nil
		}
	}
	target, ok, err := store.DefaultTarget()
	if err != nil {
		return Target{}, false, nil
	}
	return target, ok, nil
}

// validatedEndpoint parses an endpoint that did not come from a flag and checks
// it exactly as a flag would be checked. These sources are the *less* trusted
// of the two, not the more: a shell profile, a CI config or a .env file in a
// repository the user merely cloned can set one, and the host becomes a
// directory name in the credential store.
func validatedEndpoint(endpoint, source string) (Target, error) {
	t := TargetForEndpoint(endpoint)
	if err := t.Validate(); err != nil {
		return Target{}, fmt.Errorf("%s: %w", source, err)
	}
	return t, nil
}

// TargetFromEnv resolves a target from the two flag values a CLI collected,
// falling back to the environment, the last login and the default region.
func TargetFromEnv(regionFlag, endpointFlag string) (Target, error) {
	return Sources{RegionFlag: regionFlag, EndpointFlag: endpointFlag}.Resolve()
}

// OAuthTokenURL is the client-credentials token endpoint for a target. It is
// the one URL derived rather than discovered, because the client-credentials
// grant predates discovery in these CLIs and changing its shape would break
// existing CI configuration.
func OAuthTokenURL(t Target) string {
	return t.AuthServerBaseURL() + "/oauth2/token"
}
