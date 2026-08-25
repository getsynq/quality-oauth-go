package qualityoauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// legacyToken is the flat token file the per-tool OAuth copies wrote to
// ~/.synq/oauth/token_<key>.json.
type legacyToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// legacyClient is the flat client file at ~/.synq/oauth/client_<key>.json.
// CreatedAt was written as an RFC 3339 string and is read as one — an empty
// value is legitimate for a hand-written file and must not fail the read.
type legacyClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
}

// LegacyKeys are the storage keys a legacy credential may be filed under for
// one target: the hostname (synq-recon, synq-scout) plus any environment names
// the caller knows map to this target (synqctl files by env name, so only
// synqctl can supply them).
type LegacyKeys struct {
	// Keys are tried in order; the first one holding a token wins.
	Keys []string
}

// MigrationResult reports what a legacy migration moved.
type MigrationResult struct {
	// SourceKey is the legacy storage key the credential came from.
	SourceKey string
	// TokenMigrated is true when a token was copied into the new layout.
	TokenMigrated bool
	// ClientMigrated is true when a client registration was copied.
	ClientMigrated bool
}

// Migrated reports whether anything was moved.
func (r MigrationResult) Migrated() bool { return r.TokenMigrated || r.ClientMigrated }

// MigrateLegacy copies a pre-existing flat credential into the target's shared
// profile so nobody has to re-authenticate because of the store move.
//
// It is read-legacy-then-write-new and never deletes: the legacy files stay
// where they are, so an older binary on the same machine keeps working and a
// half-finished migration cannot lose a refresh token. It is also a no-op once
// the new slot holds a token, so a fresh login is never overwritten by a stale
// legacy file.
func (s *Store) MigrateLegacy(t Target, app string, keys LegacyKeys) (MigrationResult, error) {
	existing, err := s.LoadToken(t, SharedProfile)
	if err != nil {
		return MigrationResult{}, err
	}
	if existing != nil {
		return MigrationResult{}, nil
	}

	for _, key := range keys.Keys {
		if key == "" {
			continue
		}
		result, err := s.migrateLegacyKey(t, app, key)
		if err != nil {
			return MigrationResult{}, err
		}
		if result.Migrated() {
			return result, nil
		}
	}
	return MigrationResult{}, nil
}

func (s *Store) migrateLegacyKey(t Target, app, key string) (MigrationResult, error) {
	result := MigrationResult{SourceKey: key}

	var legacyTok legacyToken
	tokenPath := s.legacyTokenPath(key, t.Flow)
	found, err := readJSON(tokenPath, &legacyTok)
	if err != nil {
		return result, err
	}
	if !found || legacyTok.AccessToken == "" {
		return MigrationResult{}, nil
	}

	// The client registration comes across too — without it a refresh has no
	// client_id to present and the migrated token would be single-use.
	var legacyReg legacyClient
	clientFound, err := readJSON(s.legacyClientPath(key), &legacyReg)
	if err != nil {
		return result, err
	}
	var migratedClient *ClientRegistration
	if clientFound && legacyReg.ClientID != "" {
		// The legacy store held one registration per host regardless of which
		// tool created it, so file it under the name it was registered with —
		// that is the identity the server knows — and only fall back to the
		// migrating app when the name was never recorded.
		clientApp := firstNonEmpty(legacyReg.ClientName, app)
		createdAt, _ := time.Parse(time.RFC3339, legacyReg.CreatedAt)
		migratedClient = &ClientRegistration{
			ClientID:     legacyReg.ClientID,
			ClientSecret: legacyReg.ClientSecret,
			ClientName:   legacyReg.ClientName,
			RedirectURIs: legacyReg.RedirectURIs,
			CreatedAt:    createdAt,
		}
		if existing, err := s.LoadClient(t, clientApp); err != nil {
			return result, err
		} else if existing == nil {
			if err := s.SaveClient(t, clientApp, migratedClient); err != nil {
				return result, err
			}
			result.ClientMigrated = true
		}
	}

	// The legacy format recorded neither scopes nor workspace. Both are
	// recovered from the access token's own claims where it is a JWT; where it
	// is not, they stay empty, which `auth status` reports as unknown rather
	// than inventing a scope set.
	migrated := &Token{
		AccessToken:  legacyTok.AccessToken,
		RefreshToken: legacyTok.RefreshToken,
		TokenType:    legacyTok.TokenType,
		ExpiresAt:    legacyTok.ExpiresAt,
		// Whatever applyClaims recovers below is the token's own claim, not a
		// consented grant: the flow that minted this credential requested no
		// scopes at all, so the claim is the caller's whole envelope.
		ScopeSource: ScopeSourceClaims,
	}
	if migratedClient != nil {
		migrated.ClientID = migratedClient.ClientID
		migrated.ClientName = migratedClient.ClientName
	}
	migrated.applyClaims()
	if err := s.SaveToken(t, SharedProfile, migrated); err != nil {
		return result, err
	}
	result.TokenMigrated = true
	return result, nil
}

func (s *Store) legacyTokenPath(key, flow string) string {
	name := fmt.Sprintf("token_%s.json", key)
	if flow != "" {
		name = fmt.Sprintf("%s_token_%s.json", flow, key)
	}
	return filepath.Join(s.oauthDir(), name)
}

func (s *Store) legacyClientPath(key string) string {
	return filepath.Join(s.oauthDir(), fmt.Sprintf("client_%s.json", key))
}

// HasLegacyCredential reports whether a pre-consolidation flat credential exists
// for a target. Callers that only need to know "is this machine authenticated at
// all" use it so a user who has not run a migrating command yet is not reported
// as logged out. It reads nothing but file existence, and writes nothing.
func (s *Store) HasLegacyCredential(t Target, extraKeys ...string) bool {
	for _, key := range append([]string{t.Host}, extraKeys...) {
		if key == "" {
			continue
		}
		if _, err := os.Stat(s.legacyTokenPath(key, t.Flow)); err == nil {
			return true
		}
	}
	return false
}

// LegacyKeysPresent lists the storage keys that still have a credential in the
// pre-consolidation flat layout, sorted. `auth status` uses it to say "there is
// a credential here, it will be adopted on the next command" instead of the
// misleading "no stored credentials", which would send a still-authenticated
// user through a needless login.
func (s *Store) LegacyKeysPresent() ([]string, error) {
	entries, err := os.ReadDir(s.oauthDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", s.oauthDir(), err)
	}

	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		// token_<key>.json and <flow>_token_<key>.json were the two shapes.
		if key, ok := strings.CutPrefix(name, "token_"); ok && key != "" {
			seen[key] = struct{}{}
			continue
		}
		if _, rest, ok := strings.Cut(name, "_token_"); ok && rest != "" {
			seen[rest] = struct{}{}
		}
	}

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

// LegacyCredentialPaths lists the legacy files that exist for a key, for
// diagnostics — `auth status` mentions them so a user can see the old files are
// still there after a migration.
func (s *Store) LegacyCredentialPaths(key string) []string {
	var found []string
	for _, p := range []string{
		s.legacyClientPath(key),
		s.legacyTokenPath(key, ""),
		s.legacyTokenPath(key, FlowInternal),
	} {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	return found
}
