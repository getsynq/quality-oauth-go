package qualityoauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rogpeppe/go-internal/lockedfile"
)

const (
	// SharedProfile is the credential slot the whole toolchain reuses. One
	// login serves every CLI whose declared scopes it already covers.
	SharedProfile = "shared"

	// clientsDir holds one client registration per app, beside the profile
	// directories. Client identity belongs to the app, not to the credential
	// slot: two tools sharing one token slot must still register — and refresh
	// — as themselves, or the second login would overwrite the first tool's
	// client and leave its refresh token unusable.
	clientsDir = "clients"

	// dirPerm and filePerm are enforced in this one place: the store holds
	// refresh tokens, which are long-lived bearer credentials.
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600

	indexVersion = 1

	// lockSuffix names the advisory lock guarding a credential file. Several
	// CLIs — or several shells — can run at once, and a refresh is a
	// read-modify-write: without a lock two processes both see the stale token,
	// both refresh, and the one that writes second persists a refresh token the
	// server has already rotated away, logging the user out.
	lockSuffix = ".lock"
)

// HomeDirEnvVar overrides the credential root, for tests and for callers that
// keep credentials outside $HOME. The store itself stays at ~/.synq: the
// directory is a location on disk that existing installations already hold
// credentials in, not user-facing copy.
const HomeDirEnvVar = "QUALITY_HOME"

// ScopeSource says where a stored token's Scopes came from, which decides
// whether incremental consent may treat them as a grant to preserve.
type ScopeSource string

const (
	// ScopeSourceConsent marks scopes a login asked for and the server answered
	// with. Only these are broadened by the next login rather than replaced.
	ScopeSourceConsent ScopeSource = "consent"
	// ScopeSourceClaims marks scopes read back out of the access token's own
	// claims because nothing else recorded them — the shape every credential
	// adopted from the pre-consolidation store has.
	ScopeSourceClaims ScopeSource = "claims"
)

// Token is one stored access token. Scopes and Workspace are recorded at save
// time so `auth status` can report what a credential actually grants without a
// network call — and so a CLI can tell whether the shared token already covers
// the scopes it needs before it triggers a login.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
	// ScopeSource is the provenance of Scopes. An absent value means unknown,
	// which is treated as claims-derived: the field was added after the first
	// tokens were written, and assuming consent for those would keep an
	// unconsented envelope alive.
	ScopeSource ScopeSource `json:"scope_source,omitempty"`
	Workspace   string      `json:"workspace,omitempty"`
	Subject     string      `json:"subject,omitempty"`
	// ClientID and ClientName are the OAuth client that minted this token. A
	// refresh must present the same client, which is not necessarily the app
	// doing the refreshing — the shared slot is written by whichever tool
	// logged in last.
	ClientID   string    `json:"client_id,omitempty"`
	ClientName string    `json:"client_name,omitempty"`
	Region     string    `json:"region,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Flow       string    `json:"flow,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

// ClientRegistration is the OAuth client a profile authenticates as: either a
// seeded first-party id shipped in the binary, or the result of one dynamic
// RFC 7591 registration cached so re-login doesn't mint another client row.
type ClientRegistration struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	ClientName   string    `json:"client_name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris,omitempty"`
	SoftwareID   string    `json:"software_id,omitempty"`
	FirstParty   bool      `json:"first_party,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
}

// Index is ~/.synq/credentials.json: which regions hold credentials, which
// profiles exist under each, and which profile a bare invocation resolves to.
// It is a convenience index over the directory tree, not the source of truth —
// a missing or stale entry never hides a credential that is on disk.
type Index struct {
	Version int `json:"version"`
	// DefaultHost is the store partition a bare invocation resolves to: the
	// host of the last successful login. It is what stops someone whose only
	// deployment is AU from typing --region au on every command.
	DefaultHost string                  `json:"default_host,omitempty"`
	Regions     map[string]*IndexRegion `json:"regions,omitempty"`
}

// IndexRegion is one region's entry in the index, keyed by API host.
type IndexRegion struct {
	Region         string   `json:"region,omitempty"`
	Endpoint       string   `json:"endpoint,omitempty"`
	DefaultProfile string   `json:"default_profile,omitempty"`
	Profiles       []string `json:"profiles,omitempty"`
}

// Store is the on-disk credential store.
//
//	<root>/credentials.json                          index
//	<root>/oauth/<host>/clients/<app>.json           per-app client registration
//	<root>/oauth/<host>/<profile>/token.json         standard-flow token
//	<root>/oauth/<host>/<profile>/token-<flow>.json  alternate-flow token
//
// The host partition is what keeps EU and US credentials from clobbering each
// other; the profile partition is what keeps two CLIs from clobbering each
// other when either asks for isolation; and the separate clients directory is
// what lets several tools share one token slot while each keeps its own
// identity on the consent screen and in Settings.
type Store struct {
	root string
}

// NewStore returns a store rooted at dir.
func NewStore(dir string) *Store {
	return &Store{root: dir}
}

// DefaultStore returns the store at $QUALITY_HOME, or ~/.synq.
func DefaultStore() (*Store, error) {
	if dir := Getenv(HomeDirEnvVar); dir != "" {
		return NewStore(dir), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolving home directory: %w", err)
	}
	return NewStore(filepath.Join(home, ".synq")), nil
}

// Root is the credential root directory.
func (s *Store) Root() string { return s.root }

// IndexPath is the path of the credential index.
func (s *Store) IndexPath() string { return filepath.Join(s.root, "credentials.json") }

func (s *Store) oauthDir() string { return filepath.Join(s.root, "oauth") }

// ProfileDir is the directory holding one (host, profile) slot's credentials.
func (s *Store) ProfileDir(t Target, profile string) string {
	return filepath.Join(s.oauthDir(), t.Host, profile)
}

// ClientPath is where one app's client registration for a host lives.
func (s *Store) ClientPath(t Target, app string) string {
	return filepath.Join(s.oauthDir(), t.Host, clientsDir, app+".json")
}

// TokenPath is where a profile's token for the target's flow lives. The
// standard flow and each named flow get separate files so an admin-flow login
// never overwrites a scope-consented one.
func (s *Store) TokenPath(t Target, profile string) string {
	name := "token.json"
	if t.Flow != "" {
		name = fmt.Sprintf("token-%s.json", t.Flow)
	}
	return filepath.Join(s.ProfileDir(t, profile), name)
}

// checkSlot validates the (host, profile, flow) triple every credential path is
// built from. It is a second layer behind Target.Validate: the host reaches the
// store from a flag, an env var or a .env file, and every one of these paths
// concatenates it into a filesystem path, so refusing it here means no caller can
// place a credential outside the store by constructing a Target directly.
func (s *Store) checkSlot(t Target, profile string) error {
	if err := t.Validate(); err != nil {
		return err
	}
	return ValidateProfile(profile)
}

// LoadToken reads a profile's token, returning nil when there is none.
func (s *Store) LoadToken(t Target, profile string) (*Token, error) {
	if err := s.checkSlot(t, profile); err != nil {
		return nil, err
	}
	var tok Token
	found, err := readJSON(s.TokenPath(t, profile), &tok)
	if err != nil || !found {
		return nil, err
	}
	return &tok, nil
}

// LockToken takes the advisory lock guarding one profile's token file and
// returns the function that releases it. Hold it across a read-modify-write —
// a refresh, most importantly — so a concurrent process cannot interleave and
// persist a refresh token the server has already rotated away.
//
// The lock is advisory and per file, held by the OS, so it is released even if
// the process is killed. Callers must call the returned unlock exactly once.
func (s *Store) LockToken(t Target, profile string) (func(), error) {
	if err := s.checkSlot(t, profile); err != nil {
		return nil, err
	}
	return s.lock(s.TokenPath(t, profile))
}

// lock guards path with a sibling <path>.lock file. In-process locking is
// layered on top because a single process holding the file lock twice would
// deadlock on some platforms.
func (s *Store) lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	memMu := inProcessLock(path)
	memMu.Lock()

	unlockFile, err := lockedfile.MutexAt(path + lockSuffix).Lock()
	if err != nil {
		memMu.Unlock()
		return nil, fmt.Errorf("locking %s: %w", path+lockSuffix, err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unlockFile()
			memMu.Unlock()
		})
	}, nil
}

// inProcessLocks pairs with the file locks: goroutines in one process share a
// file descriptor table, so the OS-level lock alone would not serialise them.
var inProcessLocks sync.Map

func inProcessLock(path string) *sync.Mutex {
	actual, _ := inProcessLocks.LoadOrStore(path, &sync.Mutex{})
	mu, ok := actual.(*sync.Mutex)
	if !ok {
		// Unreachable: only *sync.Mutex is ever stored under these keys.
		return &sync.Mutex{}
	}
	return mu
}

// SaveToken writes a profile's token, stamping the target it belongs to so a
// later `auth status` can report region and endpoint offline.
func (s *Store) SaveToken(t Target, profile string, tok *Token) error {
	if err := s.checkSlot(t, profile); err != nil {
		return err
	}
	stamped := *tok
	stamped.Region = t.Region
	stamped.Endpoint = t.Endpoint
	stamped.Flow = t.Flow
	stamped.UpdatedAt = time.Now().UTC()
	if err := writeJSON(s.TokenPath(t, profile), &stamped); err != nil {
		return err
	}
	return s.recordProfile(t, profile)
}

// LoadClient reads an app's client registration for a host, returning nil when
// there is none.
func (s *Store) LoadClient(t Target, app string) (*ClientRegistration, error) {
	if err := s.checkSlot(t, app); err != nil {
		return nil, err
	}
	var reg ClientRegistration
	found, err := readJSON(s.ClientPath(t, app), &reg)
	if err != nil || !found {
		return nil, err
	}
	return &reg, nil
}

// SaveClient writes an app's client registration for a host.
func (s *Store) SaveClient(t Target, app string, reg *ClientRegistration) error {
	if err := s.checkSlot(t, app); err != nil {
		return err
	}
	return writeJSON(s.ClientPath(t, app), reg)
}

// LoadClientByID finds a stored registration by client id, so a refresh can
// present the client that actually minted the token rather than the client of
// whichever tool is doing the refreshing.
func (s *Store) LoadClientByID(t Target, clientID string) (*ClientRegistration, error) {
	if clientID == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(filepath.Join(s.oauthDir(), t.Host, clientsDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing client registrations for %s: %w", t.Host, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		app := strings.TrimSuffix(e.Name(), ".json")
		reg, err := s.LoadClient(t, app)
		if err != nil {
			return nil, err
		}
		if reg != nil && reg.ClientID == clientID {
			return reg, nil
		}
	}
	return nil, nil
}

// DeleteToken removes a profile's token for the target's flow. The client
// registration is kept: it is not a credential on its own, and dropping it
// would mint a fresh client row on the next login.
func (s *Store) DeleteToken(t Target, profile string) (bool, error) {
	if err := s.checkSlot(t, profile); err != nil {
		return false, err
	}
	err := os.Remove(s.TokenPath(t, profile))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("removing %s: %w", s.TokenPath(t, profile), err)
	}
	if !s.hasStoredToken(t.Host) {
		if err := s.ClearDefaultTarget(t.Host); err != nil {
			return true, err
		}
	}
	return true, nil
}

// DeleteProfile removes a profile's whole slot. Client registrations live
// outside the profile and are kept: dropping one mints a fresh client row on
// the next login, growing exactly the table this design set out to stop.
func (s *Store) DeleteProfile(t Target, profile string) (bool, error) {
	if err := s.checkSlot(t, profile); err != nil {
		return false, err
	}
	dir := s.ProfileDir(t, profile)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, fmt.Errorf("removing %s: %w", dir, err)
	}
	if err := s.forgetProfile(t, profile); err != nil {
		return true, err
	}
	return true, nil
}

// Profiles lists the profiles that have a directory under a target's host,
// sorted with the shared profile first.
func (s *Store) Profiles(t Target) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.oauthDir(), t.Host))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing profiles for %s: %w", t.Host, err)
	}
	var profiles []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != clientsDir {
			profiles = append(profiles, e.Name())
		}
	}
	sortProfiles(profiles)
	return profiles, nil
}

// Hosts lists every host partition that has credentials on disk, sorted. It is
// how `auth status` enumerates every region the user is logged into without
// asking the caller which regions to check.
func (s *Store) Hosts() ([]string, error) {
	entries, err := os.ReadDir(s.oauthDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing credential store: %w", err)
	}
	var hosts []string
	for _, e := range entries {
		if e.IsDir() {
			hosts = append(hosts, e.Name())
		}
	}
	sort.Strings(hosts)
	return hosts, nil
}

// LoadIndex reads the credential index, returning an empty one when absent.
func (s *Store) LoadIndex() (*Index, error) {
	idx := &Index{Version: indexVersion, Regions: map[string]*IndexRegion{}}
	found, err := readJSON(s.IndexPath(), idx)
	if err != nil {
		return nil, err
	}
	if !found {
		return &Index{Version: indexVersion, Regions: map[string]*IndexRegion{}}, nil
	}
	if idx.Regions == nil {
		idx.Regions = map[string]*IndexRegion{}
	}
	return idx, nil
}

// SaveIndex writes the credential index.
func (s *Store) SaveIndex(idx *Index) error {
	idx.Version = indexVersion
	return writeJSON(s.IndexPath(), idx)
}

// SetDefaultProfile records which profile a bare invocation against this
// target resolves to.
func (s *Store) SetDefaultProfile(t Target, profile string) error {
	return s.updateIndex(func(idx *Index) {
		entry := idx.entry(t)
		entry.DefaultProfile = profile
		entry.addProfile(profile)
	})
}

// DefaultProfile returns the profile recorded as this target's default, or
// SharedProfile when none is recorded.
func (s *Store) DefaultProfile(t Target) (string, error) {
	idx, err := s.LoadIndex()
	if err != nil {
		return "", err
	}
	if entry, ok := idx.Regions[t.Host]; ok && entry.DefaultProfile != "" {
		return entry.DefaultProfile, nil
	}
	return SharedProfile, nil
}

// SetDefaultTarget records the deployment a bare invocation resolves to, so a
// login is also a choice of deployment. Only the host is stored: it is the
// store partition, and the region name and endpoint are already indexed under
// it, so a target reconstructed later cannot disagree with the credential it
// points at.
func (s *Store) SetDefaultTarget(t Target) error {
	if err := ValidateHost(t.Host); err != nil {
		return err
	}
	return s.updateIndex(func(idx *Index) {
		idx.entry(t)
		idx.DefaultHost = t.Host
	})
}

// ClearDefaultTarget forgets the remembered deployment when it is the given
// host, and does nothing otherwise. Logging out of one region must not silently
// re-point a machine that is still logged in to another.
func (s *Store) ClearDefaultTarget(host string) error {
	return s.updateIndex(func(idx *Index) {
		if idx.DefaultHost == host {
			idx.DefaultHost = ""
		}
	})
}

// ForgetDefaultTarget drops the remembered deployment whatever it is, and
// reports whether there was one. It is what `auth use --clear` calls to go back
// to resolving the default region.
func (s *Store) ForgetDefaultTarget() (bool, error) {
	var had bool
	err := s.updateIndex(func(idx *Index) {
		had = idx.DefaultHost != ""
		idx.DefaultHost = ""
	})
	return had, err
}

// DefaultTarget returns the remembered deployment, and whether there is one.
//
// It deliberately does not check that a credential is still stored for the
// host. Logging out is what forgets a deployment (DeleteToken clears it once
// the host's last token is gone), and `auth use` may legitimately point at a
// deployment before authenticating against it — a read-side liveness check
// would send that login to the default region instead.
func (s *Store) DefaultTarget() (Target, bool, error) {
	idx, err := s.LoadIndex()
	if err != nil {
		return Target{}, false, err
	}
	if idx.DefaultHost == "" {
		return Target{}, false, nil
	}
	entry := idx.Regions[idx.DefaultHost]
	if entry != nil && entry.Endpoint != "" {
		return TargetForEndpoint(entry.Endpoint), true, nil
	}
	// An entry written before the endpoint was recorded, or a host that is a
	// named region: the region table supplies the endpoint.
	t := Target{Host: idx.DefaultHost}
	if region, ok := regionForHost(idx.DefaultHost); ok {
		t.Region = region.Name
		t.Endpoint = region.APIEndpoint
	}
	if t.Endpoint == "" {
		return Target{}, false, nil
	}
	return t, true, nil
}

// hasStoredToken reports whether any profile under the host holds a token file.
func (s *Store) hasStoredToken(host string) bool {
	base := Target{Host: host}
	profiles, err := s.Profiles(base)
	if err != nil {
		return false
	}
	for _, profile := range profiles {
		flows, err := s.tokenFlows(base, profile)
		if err != nil {
			return false
		}
		if len(flows) > 0 {
			return true
		}
	}
	return false
}

func (s *Store) recordProfile(t Target, profile string) error {
	return s.updateIndex(func(idx *Index) {
		entry := idx.entry(t)
		entry.addProfile(profile)
		if entry.DefaultProfile == "" {
			entry.DefaultProfile = SharedProfile
		}
	})
}

// updateIndex applies a change to the index under its own lock. Two CLIs
// logging in to different regions at the same time would otherwise each write a
// whole index built from a snapshot taken before the other's change, and one
// region's entry would vanish.
func (s *Store) updateIndex(mutate func(*Index)) error {
	unlock, err := s.lock(s.IndexPath())
	if err != nil {
		return err
	}
	defer unlock()

	idx, err := s.LoadIndex()
	if err != nil {
		return err
	}
	mutate(idx)
	return s.SaveIndex(idx)
}

func (s *Store) forgetProfile(t Target, profile string) error {
	return s.updateIndex(func(idx *Index) {
		entry, ok := idx.Regions[t.Host]
		if !ok {
			return
		}
		kept := entry.Profiles[:0]
		for _, p := range entry.Profiles {
			if p != profile {
				kept = append(kept, p)
			}
		}
		entry.Profiles = kept
		if entry.DefaultProfile == profile {
			entry.DefaultProfile = SharedProfile
		}
		if len(entry.Profiles) == 0 {
			delete(idx.Regions, t.Host)
			if idx.DefaultHost == t.Host {
				idx.DefaultHost = ""
			}
		}
	})
}

func (i *Index) entry(t Target) *IndexRegion {
	if i.Regions == nil {
		i.Regions = map[string]*IndexRegion{}
	}
	entry, ok := i.Regions[t.Host]
	if !ok {
		entry = &IndexRegion{}
		i.Regions[t.Host] = entry
	}
	if t.Region != "" {
		entry.Region = t.Region
	}
	if t.Endpoint != "" {
		entry.Endpoint = t.Endpoint
	}
	return entry
}

func (r *IndexRegion) addProfile(profile string) {
	for _, p := range r.Profiles {
		if p == profile {
			return
		}
	}
	r.Profiles = append(r.Profiles, profile)
	sortProfiles(r.Profiles)
}

// sortProfiles orders the shared profile first, then the rest alphabetically —
// the order `auth status` lists them in.
func sortProfiles(profiles []string) {
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i] == SharedProfile {
			return profiles[j] != SharedProfile
		}
		if profiles[j] == SharedProfile {
			return false
		}
		return profiles[i] < profiles[j]
	})
}

// ValidateProfile rejects a profile name that would escape its host partition
// or collide with the store's own files. Profile names reach the store from
// --auth-profile, so they are user input.
func ValidateProfile(profile string) error {
	if profile == "" {
		return errors.New("profile name is empty")
	}
	if profile != filepath.Clean(profile) || strings.ContainsAny(profile, `/\`) || profile == "." || profile == ".." {
		return fmt.Errorf("invalid profile name %q: expected a single path segment", profile)
	}
	if profile == clientsDir {
		return fmt.Errorf("invalid profile name %q: reserved for client registrations", profile)
	}
	return nil
}

// readJSON reads a credential file under a shared lock, so a concurrent writer
// can never be observed mid-write.
func readJSON(path string, into any) (bool, error) {
	data, err := lockedfile.Read(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(data, into); err != nil {
		return false, fmt.Errorf("parsing %s: %w", path, err)
	}
	return true, nil
}

// writeJSON writes atomically via a temp file in the destination directory, so
// a crash mid-write cannot leave a truncated token file behind. Mutual exclusion
// against another process is the caller's job, via Store.lock — atomicity alone
// only guarantees that a reader sees one version or the other, not that two
// read-modify-write cycles do not lose one of their updates.
func writeJSON(path string, from any) error {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(from, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", filepath.Dir(path), err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpName, path, err)
	}
	return nil
}
