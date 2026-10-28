package qualityoauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// App identifies one of our CLIs to the authorization server and to the
// credential store. Name is both the registered client_name a user sees in
// Settings and the per-app store namespace, so two CLIs on one machine can no
// longer register as each other or overwrite each other's token.
type App struct {
	// Name is the tool's name, e.g. "synq-recon".
	Name string
	// Version is reported as software_version on registration.
	Version string
	// SoftwareID is stable across versions and machines, so the server can
	// recognise repeat registrations of the same tool.
	SoftwareID string
	// Scopes are the scopes this tool actually needs. They are sent as the
	// `scope` parameter, which is what lets consent pre-check exactly these
	// instead of offering the user's whole envelope.
	Scopes []string
	// FirstPartyClientID is the fixed public client id seeded for this tool.
	// When set, dynamic registration is skipped entirely — the gh / gcloud /
	// stripe model — so re-login stops adding a client row per machine.
	FirstPartyClientID string
	// CallbackPorts are the loopback ports to try; nil uses DefaultCallbackPorts.
	CallbackPorts []int
	// ClientURI, LogoURI, PolicyURI and TosURI are RFC 7591 metadata shown on
	// the consent screen.
	ClientURI string
	LogoURI   string
	PolicyURI string
	TosURI    string
}

// AuthProfileEnvVar selects a credential profile without a flag.
const AuthProfileEnvVar = "QUALITY_AUTH_PROFILE"

// options are the knobs Login/Token/Logout share.
type options struct {
	store        *Store
	profile      string
	isolated     bool
	flow         string
	extraScopes  []string
	clientID     string
	clientSecret string
	coalesce     bool
	organization string
	httpClient   *http.Client
	openBrowser  func(string) error
	logger       *slog.Logger
}

// Option customises a Login, Token or Logout call.
type Option func(*options)

// WithStore overrides the credential store. Tests and callers keeping
// credentials outside ~/.synq use this.
func WithStore(s *Store) Option { return func(o *options) { o.store = s } }

// WithProfile pins the credential profile, e.g. from --auth-profile.
func WithProfile(profile string) Option { return func(o *options) { o.profile = profile } }

// WithIsolated writes and reads this app's own profile instead of the shared
// one — the escape hatch for holding two differently-scoped tokens for the same
// region on one machine.
func WithIsolated() Option { return func(o *options) { o.isolated = true } }

// WithFlow selects an authorization-server authorize flavour, e.g. FlowInternal.
func WithFlow(flow string) Option { return func(o *options) { o.flow = flow } }

// WithExtraScopes asks for scopes beyond the app's declared set.
func WithExtraScopes(scopes ...string) Option {
	return func(o *options) { o.extraScopes = append(o.extraScopes, scopes...) }
}

// WithHTTPClient overrides the HTTP client used for discovery, registration and
// token exchange.
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.httpClient = c } }

// WithBrowserOpener overrides how the authorization URL is opened.
func WithBrowserOpener(open func(string) error) Option {
	return func(o *options) { o.openBrowser = open }
}

// WithLogger overrides the logger progress is reported on; the default is
// slog.Default().
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

// WithClientOverride authenticates as a caller-supplied OAuth client instead of
// the app's own registration — the `--client-id` / `--client-secret` escape hatch
// for authenticating as a specific, possibly confidential, client. The
// registration is cached under the app's name so a refresh can present the same
// client.
func WithClientOverride(clientID, clientSecret string) Option {
	return func(o *options) {
		o.clientID = clientID
		o.clientSecret = clientSecret
	}
}

// WithCoalesceLogin logs in with the Coalesce login the deployment advertises
// (`cli_login` in its discovery document) instead of the deployment's own
// authorization server. The token carries the user's Quality roles rather than
// consented scopes, and is refreshed at the Coalesce issuer. The issuer only
// accepts DefaultCallbackPorts, so an App overriding CallbackPorts cannot use it.
func WithCoalesceLogin() Option { return func(o *options) { o.coalesce = true } }

// WithOrganization picks the Coalesce organization a Coalesce login is for.
// Without it the issuer asks the user to choose one.
func WithOrganization(orgID string) Option { return func(o *options) { o.organization = orgID } }

// CoalesceLoginScopes are the OIDC scopes a Coalesce login asks for;
// offline_access is what yields a refresh token.
var CoalesceLoginScopes = []string{"openid", "profile", "email", "offline_access"}

func (a App) resolveOptions(opts []Option) (*options, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	if o.organization != "" && !o.coalesce {
		return nil, errors.New("an organization applies only to a Coalesce login")
	}
	if o.store == nil {
		s, err := DefaultStore()
		if err != nil {
			return nil, err
		}
		o.store = s
	}
	if o.profile == "" {
		o.profile = Getenv(AuthProfileEnvVar)
	}
	if o.isolated && o.profile == "" {
		o.profile = a.Name
	}
	if o.profile != "" {
		if err := ValidateProfile(o.profile); err != nil {
			return nil, err
		}
	}
	o.logger = logger(o.logger).With("app", a.Name)
	return o, nil
}

func (a App) ports() []int {
	if len(a.CallbackPorts) > 0 {
		return a.CallbackPorts
	}
	return DefaultCallbackPorts
}

// requestedScopes is what a login asks for: the app's declared needs plus
// anything the caller added.
func (a App) requestedScopes(o *options) []string {
	return UnionScopes(a.Scopes, o.extraScopes)
}

// CredentialSource says which store slot a resolved credential came from.
type CredentialSource string

const (
	// SourceProfile means an explicitly requested profile.
	SourceProfile CredentialSource = "profile"
	// SourcePerApp means this app's own profile.
	SourcePerApp CredentialSource = "per-app"
	// SourceShared means the shared profile the whole toolchain reuses.
	SourceShared CredentialSource = "shared"
)

// Credential is a resolved, usable token plus where it came from.
type Credential struct {
	Token   *Token
	Profile string
	Source  CredentialSource
	// MissingScopes are scopes the app needs that this credential does not
	// carry. It is empty for a credential that fully covers the app, and
	// non-empty only when nothing better was available.
	MissingScopes []string
}

// ErrNoCredentials is returned when no stored credential can serve the app and
// a browser login is required. Callers match on it to print their own
// tool-specific "run <tool> auth login" guidance.
var ErrNoCredentials = errors.New("no stored credentials")

// Login runs the browser flow for a target and stores the result.
//
// By default it writes the shared profile, so one login serves the whole
// toolchain. When the shared profile already holds a token that lacks a scope
// this app needs, the flow asks for granted ∪ needed rather than narrowing the
// existing grant — the incremental-consent case.
func (a App) Login(ctx context.Context, target Target, opts ...Option) (*Token, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return nil, err
	}
	if o.flow != "" {
		target = target.WithFlow(o.flow)
	}
	profile := o.profile
	if profile == "" {
		profile = SharedProfile
	}

	meta, err := Discover(ctx, o.httpClient, target)
	if err != nil {
		return nil, fmt.Errorf("discovering the authorization server for %s: %w", target, err)
	}
	o.logger.DebugContext(ctx, "Discovered the authorization server", "issuer", meta.Issuer, "target", target.String())

	var tok *Token
	if o.coalesce {
		tok, err = a.coalesceLogin(ctx, o, target, meta)
	} else {
		tok, err = a.qualityLogin(ctx, o, target, profile, meta)
	}
	if err != nil {
		return nil, err
	}
	if err := o.store.SaveToken(target, profile, tok); err != nil {
		return nil, err
	}
	// A login is also a choice of deployment: without this, someone whose only
	// deployment is AU has to pass --region au to every later command, because
	// nothing but the default region would be left to resolve from.
	if err := o.store.SetDefaultTarget(target); err != nil {
		return nil, err
	}
	return tok, nil
}

// qualityLogin runs the consent flow against the deployment's own
// authorization server.
func (a App) qualityLogin(ctx context.Context, o *options, target Target, profile string, meta *ServerMetadata) (*Token, error) {
	scopes := a.requestedScopes(o)
	if existing, err := o.store.LoadToken(target, profile); err != nil {
		return nil, err
	} else if consented := existing.ConsentedScopes(); len(consented) > 0 {
		scopes = UnionScopes(consented, scopes)
	}

	listener, redirectURI, err := ListenOnCallbackPort(a.ports())
	if err != nil {
		return nil, err
	}

	client, err := a.resolveClient(ctx, o, target, meta, scopes)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	result, err := RunAuthorizationCodeFlow(ctx, FlowRequest{
		Metadata:     meta,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		Listener:     listener,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
		Flow:         target.Flow,
		OpenBrowser:  o.openBrowser,
		Logger:       o.logger,
		HTTPClient:   o.httpClient,
	})
	if err != nil {
		return nil, err
	}

	tok := &Token{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    result.ExpiresAt,
		Scopes:       dedupeScopes(result.GrantedScopes),
		// A consent screen just answered a request that carried this app's scope
		// set, so this is the one provenance the next login may broaden from.
		ScopeSource: ScopeSourceConsent,
		ClientID:    client.ClientID,
		ClientName:  client.ClientName,
	}
	tok.applyClaims()
	return tok, nil
}

// coalesceLogin runs the authorization-code flow against the Coalesce issuer
// the deployment advertises, as the advertised public client. Nothing is
// registered or cached for the client: the deployment owns it, not this machine.
func (a App) coalesceLogin(ctx context.Context, o *options, target Target, meta *ServerMetadata) (*Token, error) {
	if target.Flow != "" {
		return nil, fmt.Errorf("a Coalesce login has no %q flow", target.Flow)
	}
	offer := meta.CliLogin
	if offer == nil || offer.Issuer == "" || offer.ClientID == "" {
		return nil, fmt.Errorf("%s offers no Coalesce login", target)
	}
	oidc, err := DiscoverOIDC(ctx, o.httpClient, offer.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering the Coalesce login at %s: %w", offer.Issuer, err)
	}
	clientID, clientSecret := offer.ClientID, ""
	if o.clientID != "" {
		clientID, clientSecret = o.clientID, o.clientSecret
	}

	listener, redirectURI, err := ListenOnCallbackPort(a.ports())
	if err != nil {
		return nil, err
	}
	result, err := RunAuthorizationCodeFlow(ctx, FlowRequest{
		Metadata:     oidc,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Listener:     listener,
		RedirectURI:  redirectURI,
		Scopes:       CoalesceLoginScopes,
		Audience:     offer.Audience,
		Organization: o.organization,
		OpenBrowser:  o.openBrowser,
		Logger:       o.logger,
		HTTPClient:   o.httpClient,
	})
	if err != nil {
		return nil, err
	}

	tok := &Token{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    result.ExpiresAt,
		ClientID:     clientID,
		ClientName:   a.Name,
		Issuer:       offer.Issuer,
	}
	tok.applyClaims()
	// The deployment rejects a Coalesce token without both, so failing here
	// beats a login that looks fine and then fails every call.
	if tok.Workspace == "" {
		return nil, fmt.Errorf("the Coalesce organization you logged in to has no Coalesce Quality workspace on %s", target)
	}
	if len(tok.Roles) == 0 {
		return nil, fmt.Errorf("your Coalesce login grants no Coalesce Quality role in workspace %q", tok.Workspace)
	}
	return tok, nil
}

// resolveClient returns the OAuth client to authenticate as: the seeded
// first-party id when the app has one, otherwise a cached or freshly
// registered dynamic client.
func (a App) resolveClient(
	ctx context.Context,
	o *options,
	target Target,
	meta *ServerMetadata,
	scopes []string,
) (*ClientRegistration, error) {
	// A caller-supplied client wins over everything: the operator is explicitly
	// asking to authenticate as that client. Cache it so the refresh presents
	// the same one, secret included.
	if o.clientID != "" {
		reg := &ClientRegistration{
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
			ClientName:   a.Name,
			CreatedAt:    time.Now().UTC(),
		}
		if err := o.store.SaveClient(target, a.Name, reg); err != nil {
			return nil, err
		}
		o.logger.InfoContext(ctx, "Authenticating as the supplied OAuth client", "client_id", reg.ClientID)
		return reg, nil
	}

	if a.FirstPartyClientID != "" {
		return &ClientRegistration{
			ClientID:   a.FirstPartyClientID,
			ClientName: a.Name,
			SoftwareID: a.SoftwareID,
			FirstParty: true,
		}, nil
	}

	cached, err := o.store.LoadClient(target, a.Name)
	if err != nil {
		return nil, err
	}
	if cached != nil && cached.ClientID != "" {
		o.logger.DebugContext(ctx, "Reusing the cached client registration", "client_id", cached.ClientID)
		return cached, nil
	}

	o.logger.InfoContext(ctx, "Registering with the authorization server")
	reg, err := Register(ctx, o.httpClient, meta.RegistrationEndpoint, RegistrationRequest{
		ClientName:              a.Name,
		RedirectURIs:            CallbackRedirectURIs(a.ports()),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "none",
		ApplicationType:         "native",
		ClientURI:               a.ClientURI,
		LogoURI:                 a.LogoURI,
		PolicyURI:               a.PolicyURI,
		TosURI:                  a.TosURI,
		SoftwareID:              a.SoftwareID,
		SoftwareVersion:         a.Version,
		Scope:                   scopeString(scopes),
	})
	if err != nil {
		return nil, err
	}
	o.logger.InfoContext(ctx, "Registered a client", "client_name", reg.ClientName, "client_id", reg.ClientID)
	if err := o.store.SaveClient(target, a.Name, reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// Token resolves a usable access token for the target, refreshing it if needed.
// It never opens a browser: a caller with nothing usable gets ErrNoCredentials
// so it can print its own login instructions.
func (a App) Token(ctx context.Context, target Target, opts ...Option) (*Token, error) {
	cred, err := a.Credential(ctx, target, opts...)
	if err != nil {
		return nil, err
	}
	return cred.Token, nil
}

// Credential resolves a usable credential for the target, refreshing it if
// needed, and reports which slot it came from.
//
// Resolution order after the environment-variable paths a CLI checks first
// (SYNQ_CLIENT_ID/SYNQ_CLIENT_SECRET, SYNQ_TOKEN — see EnvCredential):
//
//  1. an explicitly requested profile (--auth-profile / SYNQ_AUTH_PROFILE);
//  2. this app's own profile, when one exists;
//  3. the shared profile, when its granted scopes cover the app's needs.
//
// A shared token whose scopes are unknown (migrated from the legacy store,
// which never recorded them) is accepted: it predates scope narrowing and is
// most likely broad. A shared token that is known to be missing a scope is
// still returned, with MissingScopes set, so the caller can decide between
// re-consenting and proceeding.
func (a App) Credential(ctx context.Context, target Target, opts ...Option) (*Credential, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return nil, err
	}
	if o.flow != "" {
		target = target.WithFlow(o.flow)
	}

	if o.profile != "" {
		cred, err := a.credentialFrom(ctx, o, target, o.profile, SourceProfile)
		if err != nil {
			return nil, err
		}
		if cred == nil {
			return nil, fmt.Errorf("%w in profile %q for %s", ErrNoCredentials, o.profile, target)
		}
		return cred, nil
	}

	if cred, err := a.credentialFrom(ctx, o, target, a.Name, SourcePerApp); err != nil {
		return nil, err
	} else if cred != nil {
		return cred, nil
	}

	cred, err := a.credentialFrom(ctx, o, target, SharedProfile, SourceShared)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("%w for %s", ErrNoCredentials, target)
	}
	return cred, nil
}

// credentialFrom loads one profile's token and refreshes it when stale.
// A nil credential with a nil error means "this slot holds nothing usable".
func (a App) credentialFrom(
	ctx context.Context,
	o *options,
	target Target,
	profile string,
	source CredentialSource,
) (*Credential, error) {
	tok, err := o.store.LoadToken(target, profile)
	if err != nil {
		return nil, err
	}
	if tok == nil || tok.AccessToken == "" {
		return nil, nil
	}

	if !tok.Valid() {
		refreshed, err := a.refresh(ctx, o, target, profile, tok)
		if err != nil {
			return nil, err
		}
		if refreshed == nil {
			return nil, nil
		}
		tok = refreshed
	}

	// An empty recorded scope set means "not recorded", not "no scopes" — a
	// legacy-migrated token has no scope list and must not be reported as
	// missing everything.
	var missing []string
	if len(tok.Scopes) > 0 {
		missing = MissingScopes(tok.Scopes, a.Scopes)
	}
	return &Credential{Token: tok, Profile: profile, Source: source, MissingScopes: missing}, nil
}

// refresh renews an expired token. It returns a nil token and a nil error when
// the token cannot be renewed without a browser, so the caller can fall through
// to the next slot instead of failing the whole resolution.
func (a App) refresh(ctx context.Context, o *options, target Target, profile string, stale *Token) (*Token, error) {
	if !stale.Refreshable() {
		return nil, nil
	}

	// The lock spans the whole read-modify-write and is held by the OS, so it
	// serialises other goroutines and other CLI processes alike. Without it two
	// concurrent commands both see the stale token, both refresh, and whichever
	// writes second persists a refresh token the server has already rotated
	// away — logging the user out.
	unlock, err := o.store.LockToken(target, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Re-read under the lock: another goroutine, or another process that got
	// here first, may already have refreshed this slot.
	if current, err := o.store.LoadToken(target, profile); err != nil {
		return nil, err
	} else if current != nil && current.Valid() {
		return current, nil
	} else if current != nil {
		stale = current
	}

	var fresh *Token
	if stale.CoalesceLogin() {
		fresh, err = a.refreshCoalesce(ctx, o, target, profile, stale)
	} else {
		fresh, err = a.refreshQuality(ctx, o, target, profile, stale)
	}
	if err != nil {
		return nil, err
	}
	if err := o.store.SaveToken(target, profile, fresh); err != nil {
		return nil, err
	}
	o.logger.InfoContext(ctx, "Refreshed a stored credential",
		"profile", profile, "target", target.String(), "expires_at", fresh.ExpiresAt.Format(time.RFC3339))
	return fresh, nil
}

// refreshQuality renews a token at the deployment's own authorization server.
func (a App) refreshQuality(ctx context.Context, o *options, target Target, profile string, stale *Token) (*Token, error) {
	client, err := a.refreshClient(o, target, stale)
	if err != nil {
		return nil, err
	}

	meta, err := Discover(ctx, o.httpClient, target)
	if err != nil {
		return nil, fmt.Errorf("discovering the authorization server for %s: %w", target, err)
	}

	result, err := Refresh(ctx, o.httpClient, meta, client.ClientID, client.ClientSecret, stale.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refreshing the %s credential for %s: %w", profile, target, err)
	}

	// A server that does not rotate the refresh token returns none; keeping
	// the old one is what makes the next refresh work.
	refreshToken := result.RefreshToken
	if refreshToken == "" {
		refreshToken = stale.RefreshToken
	}
	scopes := dedupeScopes(result.GrantedScopes)
	if len(scopes) == 0 {
		scopes = stale.Scopes
	}

	fresh := &Token{
		AccessToken:  result.AccessToken,
		RefreshToken: refreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    result.ExpiresAt,
		Scopes:       scopes,
		// Provenance is inherited: renewing a grant is not consenting to one, so
		// a refresh cannot turn a claims-derived envelope into an approved set.
		ScopeSource: stale.ScopeSource,
		Workspace:   stale.Workspace,
		Subject:     stale.Subject,
		ClientID:    client.ClientID,
		ClientName:  firstNonEmpty(client.ClientName, stale.ClientName),
	}
	fresh.applyClaims()
	return fresh, nil
}

// refreshCoalesce renews a Coalesce login's token at the issuer and as the
// client that minted it: a refresh token is valid nowhere else. The issuer
// rotates refresh tokens, so the returned one must be the one persisted.
func (a App) refreshCoalesce(ctx context.Context, o *options, target Target, profile string, stale *Token) (*Token, error) {
	if stale.ClientID == "" {
		return nil, fmt.Errorf("the stored Coalesce credential for %s records no OAuth client, so it cannot be refreshed", target)
	}
	oidc, err := DiscoverOIDC(ctx, o.httpClient, stale.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering the Coalesce login at %s: %w", stale.Issuer, err)
	}
	result, err := Refresh(ctx, o.httpClient, oidc, stale.ClientID, "", stale.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refreshing the %s credential for %s at %s: %w", profile, target, stale.Issuer, err)
	}

	refreshToken := result.RefreshToken
	if refreshToken == "" {
		refreshToken = stale.RefreshToken
	}
	fresh := &Token{
		AccessToken:  result.AccessToken,
		RefreshToken: refreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    result.ExpiresAt,
		Workspace:    stale.Workspace,
		Subject:      stale.Subject,
		ClientID:     stale.ClientID,
		ClientName:   stale.ClientName,
		Issuer:       stale.Issuer,
		Roles:        stale.Roles,
		Organization: stale.Organization,
	}
	fresh.applyClaims()
	return fresh, nil
}

// refreshClient is the client a refresh must present: the one that minted the
// token, which in the shared slot is whichever tool logged in last rather than
// the tool now doing the refresh. Presenting a different client_id makes the
// token endpoint reject the grant.
func (a App) refreshClient(o *options, target Target, stale *Token) (*ClientRegistration, error) {
	if stale.ClientID != "" {
		if stale.ClientID == a.FirstPartyClientID {
			return &ClientRegistration{ClientID: stale.ClientID, ClientName: a.Name, FirstParty: true}, nil
		}
		// A stored registration supplies the secret for the rare confidential
		// client; a public client legitimately has none, so an unknown id is
		// still usable as a bare public client id.
		if known, err := o.store.LoadClientByID(target, stale.ClientID); err != nil {
			return nil, err
		} else if known != nil {
			return known, nil
		}
		return &ClientRegistration{ClientID: stale.ClientID, ClientName: stale.ClientName}, nil
	}

	// Tokens written before the minting client was recorded fall back to this
	// app's own client, which is the best guess available.
	if a.FirstPartyClientID != "" {
		return &ClientRegistration{ClientID: a.FirstPartyClientID, ClientName: a.Name, FirstParty: true}, nil
	}
	client, err := o.store.LoadClient(target, a.Name)
	if err != nil {
		return nil, err
	}
	if client == nil || client.ClientID == "" {
		return nil, fmt.Errorf(
			"the stored credential for %s records no OAuth client, so it cannot be refreshed",
			target,
		)
	}
	return client, nil
}

// Logout removes the target's stored token for this app's resolved profile.
func (a App) Logout(ctx context.Context, target Target, opts ...Option) (bool, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return false, err
	}
	if o.flow != "" {
		target = target.WithFlow(o.flow)
	}
	profile := o.profile
	if profile == "" {
		profile = SharedProfile
	}
	return o.store.DeleteToken(target, profile)
}

// DefaultTarget returns the deployment a bare invocation resolves to — the one
// the last login recorded — and whether there is one.
func (a App) DefaultTarget(opts ...Option) (Target, bool, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return Target{}, false, err
	}
	return o.store.DefaultTarget()
}

// SetDefaultTarget records the deployment a bare invocation resolves to,
// without logging in. It is the explicit form of what a login does implicitly,
// for switching between two deployments you are already authenticated against.
func (a App) SetDefaultTarget(target Target, opts ...Option) error {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return err
	}
	return o.store.SetDefaultTarget(target)
}

// ForgetDefaultTarget drops the remembered deployment, so resolution falls back
// to the default region. It reports whether there was one to drop.
func (a App) ForgetDefaultTarget(opts ...Option) (bool, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return false, err
	}
	return o.store.ForgetDefaultTarget()
}

// ExpireStoredToken backdates a stored token's expiry so the next resolution
// refreshes it unconditionally, and reports whether there was a token to
// backdate. A "refresh now" command needs this: resolution renews only a stale
// credential, so without it the command would silently do nothing whenever the
// token happened to still be valid — and proving the refresh token still works
// is the whole point of asking.
func (a App) ExpireStoredToken(target Target, opts ...Option) (bool, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return false, err
	}
	if o.flow != "" {
		target = target.WithFlow(o.flow)
	}
	profile := o.profile
	if profile == "" {
		profile = SharedProfile
	}

	unlock, err := o.store.LockToken(target, profile)
	if err != nil {
		return false, err
	}
	defer unlock()

	tok, err := o.store.LoadToken(target, profile)
	if err != nil {
		return false, err
	}
	if tok == nil || tok.AccessToken == "" {
		return false, nil
	}
	if !tok.Refreshable() {
		return false, fmt.Errorf(
			"the stored credential for %s cannot be refreshed: it carries no refresh token",
			target,
		)
	}
	tok.ExpiresAt = time.Now().Add(-time.Minute)
	if err := o.store.SaveToken(target, profile, tok); err != nil {
		return false, err
	}
	return true, nil
}

// LegacyCredentialKeys lists the storage keys that still hold a credential in
// the pre-consolidation flat layout. They are adopted on the next command that
// authenticates; reporting them lets `auth status` avoid claiming a still-
// authenticated machine has no credentials.
func (a App) LegacyCredentialKeys(opts ...Option) ([]string, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return nil, err
	}
	return o.store.LegacyKeysPresent()
}

// HasStoredCredential reports whether the target has a credential this app could
// use — a valid or refreshable one in the store, or a not-yet-migrated legacy
// one. It reads local files only; it neither refreshes nor migrates, so it is
// safe on a validation path.
func (a App) HasStoredCredential(target Target, extraLegacyKeys []string, opts ...Option) bool {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return false
	}
	if o.flow != "" {
		target = target.WithFlow(o.flow)
	}

	statuses, err := o.store.StatusForHost(target.Host)
	if err == nil {
		for _, st := range statuses {
			if st.Flow != target.Flow {
				continue
			}
			// An expired credential still counts when it can be renewed without
			// a browser — the next call refreshes it.
			if st.Valid || st.Refreshable {
				return true
			}
		}
	}
	return o.store.HasLegacyCredential(target, extraLegacyKeys...)
}

// MigrateLegacyCredentials copies any pre-existing flat credential for the
// target into the shared profile. It is a no-op once the new slot is populated
// and never deletes the legacy files, so nobody has to re-authenticate because
// of the store move and an older binary keeps working.
//
// hostKeys are the extra legacy storage keys the caller knows map to this
// target (synqctl filed credentials by environment name, so only synqctl can
// supply those); the target's own hostname is always tried.
func (a App) MigrateLegacyCredentials(target Target, extraKeys []string, opts ...Option) (MigrationResult, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return MigrationResult{}, err
	}
	if o.flow != "" {
		target = target.WithFlow(o.flow)
	}
	return o.store.MigrateLegacy(target, a.Name, LegacyKeys{Keys: append([]string{target.Host}, extraKeys...)})
}
