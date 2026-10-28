package qualityoauth

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"time"
)

// Status describes one stored credential. Every field is read from disk, so
// `auth status` can list every region a user is logged into — with workspace,
// scopes and expiry — without a single network call.
type Status struct {
	// Region is the named region, or "" for a custom endpoint.
	Region string
	// Endpoint is the API endpoint the credential was minted for.
	Endpoint string
	// Host is the store partition, always populated even for a token file that
	// predates endpoint stamping.
	Host string
	// Profile is the credential slot, e.g. "shared" or "synq-recon".
	Profile string
	// Flow is "" for the standard consent flow, or e.g. "internal".
	Flow string
	// Workspace the token is scoped to, "" when it was never recorded.
	Workspace string
	// Scopes the token carries, nil when they were never recorded (a
	// legacy-migrated credential).
	Scopes []string
	// Issuer is the Coalesce issuer of a Coalesce login, "" otherwise.
	Issuer string
	// Roles and Organization are a Coalesce login's Quality roles and
	// Coalesce organization.
	Roles        []string
	Organization string
	// ExpiresAt is the access token's expiry; zero when unknown.
	ExpiresAt time.Time
	// Valid reports whether the access token is usable now, clock skew included.
	Valid bool
	// Refreshable reports whether an expired token can be renewed silently.
	Refreshable bool
	// ClientID and ClientName identify the OAuth client the credential belongs
	// to. A first-party credential carries the seeded id.
	ClientID   string
	ClientName string
	// TokenPath is where the credential lives, for troubleshooting.
	TokenPath string
}

// Expired reports whether the credential has passed its expiry outright, as
// opposed to merely being inside the skew window.
func (s Status) Expired() bool {
	return !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt)
}

// CoversScopes reports whether the credential carries every scope in needed. A
// credential with no recorded scopes answers true: the scope set is unknown,
// not empty, and claiming otherwise would report every migrated credential as
// broken.
func (s Status) CoversScopes(needed []string) bool {
	if len(s.Scopes) == 0 {
		return true
	}
	return ScopesCover(s.Scopes, needed)
}

// Status lists every stored credential across every region, ordered by host
// then profile. It performs no network I/O.
func (a App) Status(ctx context.Context, opts ...Option) ([]Status, error) {
	o, err := a.resolveOptions(opts)
	if err != nil {
		return nil, err
	}
	return o.store.Status(ctx)
}

// Status lists every credential in the store.
func (s *Store) Status(ctx context.Context) ([]Status, error) {
	hosts, err := s.Hosts()
	if err != nil {
		return nil, err
	}
	var all []Status
	for _, host := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hostStatus, err := s.StatusForHost(host)
		if err != nil {
			return nil, err
		}
		all = append(all, hostStatus...)
	}
	return all, nil
}

// StatusForHost lists the credentials stored under one host partition.
func (s *Store) StatusForHost(host string) ([]Status, error) {
	// The Target is reconstructed from the directory name so a partition
	// written by a newer binary (or a host with no named region) still reads.
	base := Target{Host: host}
	if region, ok := regionForHost(host); ok {
		base.Region = region.Name
		base.Endpoint = region.APIEndpoint
	}

	profiles, err := s.Profiles(base)
	if err != nil {
		return nil, err
	}

	var out []Status
	for _, profile := range profiles {
		flows, err := s.tokenFlows(base, profile)
		if err != nil {
			return nil, err
		}
		for _, flow := range flows {
			target := base.WithFlow(flow)
			tok, err := s.LoadToken(target, profile)
			if err != nil {
				return nil, err
			}
			if tok == nil {
				continue
			}
			st, err := s.statusFor(target, profile, tok)
			if err != nil {
				return nil, err
			}
			out = append(out, st)
		}
	}
	return out, nil
}

// statusFor renders one stored token.
//
// The client identity comes from the token, which records the client that minted
// it. A registration file is only consulted to fill in a name the token does not
// carry, and looked up by client id — never by profile. Client registrations are
// keyed by app name (`clients/<app>.json`), so reading one by profile silently
// found nothing for the shared profile (the default) and happened to work only
// for a per-app profile whose name equalled the app's, which is what made the gap
// invisible.
func (s *Store) statusFor(target Target, profile string, tok *Token) (Status, error) {
	st := Status{
		Region:       firstNonEmpty(tok.Region, target.Region),
		Endpoint:     firstNonEmpty(tok.Endpoint, target.Endpoint),
		Host:         target.Host,
		Profile:      profile,
		Flow:         target.Flow,
		Workspace:    tok.Workspace,
		Scopes:       tok.Scopes,
		Issuer:       tok.Issuer,
		Roles:        tok.Roles,
		Organization: tok.Organization,
		ExpiresAt:    tok.ExpiresAt,
		Valid:        tok.Valid(),
		Refreshable:  tok.Refreshable(),
		ClientID:     tok.ClientID,
		ClientName:   tok.ClientName,
		TokenPath:    s.TokenPath(target, profile),
	}

	if st.ClientID != "" && st.ClientName == "" {
		reg, err := s.LoadClientByID(target, st.ClientID)
		if err != nil {
			return Status{}, err
		}
		if reg != nil {
			st.ClientName = reg.ClientName
		}
	}
	return st, nil
}

// tokenFlows lists the flows a profile holds a token for, standard flow first.
func (s *Store) tokenFlows(t Target, profile string) ([]string, error) {
	entries, err := os.ReadDir(s.ProfileDir(t, profile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var flows []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "token.json" {
			flows = append(flows, "")
			continue
		}
		if flow, ok := strings.CutPrefix(name, "token-"); ok {
			if flow, ok := strings.CutSuffix(flow, ".json"); ok && flow != "" {
				flows = append(flows, flow)
			}
		}
	}
	sort.Strings(flows)
	return flows, nil
}

func regionForHost(host string) (Region, bool) {
	for _, r := range regions {
		if t := TargetForEndpoint(r.APIEndpoint); t.Host == host {
			return r, true
		}
	}
	return Region{}, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
