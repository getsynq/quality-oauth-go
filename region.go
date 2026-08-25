package qualityoauth

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Region is a named Coalesce Quality deployment. Adding a deployment is one
// entry in regions below and no other code change: the store partitions on
// APIEndpoint's host, and every OAuth endpoint is discovered from that host's
// /.well-known/oauth-authorization-server.
type Region struct {
	// Name is the value accepted by --region.
	Name string
	// APIEndpoint is the public gRPC target, host:port.
	APIEndpoint string
	// AppURL is the web app a human logs in to, for display only.
	AppURL string
}

// regions is the named-region table. The issuer, authorization endpoint and
// token endpoint are deliberately absent — they differ per region and are
// always discovered, never derived from another region's values.
var regions = []Region{
	{Name: "eu", APIEndpoint: "developer.synq.io:443", AppURL: "https://app.synq.io"},
	{Name: "us", APIEndpoint: "api.us.synq.io:443", AppURL: "https://app.us.synq.io"},
	{Name: "au", APIEndpoint: "api.au.synq.io:443", AppURL: "https://app.au.synq.io"},
}

// DefaultRegion is used when neither --region nor an explicit endpoint is given.
const DefaultRegion = "eu"

// RegionNames returns the known region names, sorted, for flag help and errors.
func RegionNames() []string {
	names := make([]string, 0, len(regions))
	for _, r := range regions {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// LookupRegion returns the named region.
func LookupRegion(name string) (Region, bool) {
	for _, r := range regions {
		if strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return Region{}, false
}

// Target is a resolved place to authenticate against: one API endpoint, the
// auth-server base URL derived from its host, and the store partition key.
// A token minted for one Target is never sent to another.
type Target struct {
	// Region is the named region, or "" for a custom endpoint.
	Region string
	// Endpoint is the gRPC target, host:port.
	Endpoint string
	// Host is Endpoint without the port. It is the store partition key.
	Host string
	// Flow selects the authorize flavour: "" for the standard
	// scope-consent path, "internal" for the admin allow-list path. It gets
	// its own token slot so the two never overwrite each other.
	Flow string
}

// AuthServerBaseURL is the origin the OAuth discovery document is fetched from.
func (t Target) AuthServerBaseURL() string {
	if t.Host == "localhost" || strings.HasPrefix(t.Host, "127.0.0.") {
		return "http://" + t.Endpoint
	}
	return "https://" + t.Host
}

// String renders the target for CLI output.
func (t Target) String() string {
	if t.Region != "" {
		return fmt.Sprintf("%s (%s)", t.Region, t.Endpoint)
	}
	return t.Endpoint
}

// hostPattern is what a host must look like to be usable: DNS labels or an IP
// literal. It deliberately excludes path separators, "." and ".." — the host is a
// directory name in the credential store, so anything else could place a
// credential outside it.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:\[\]-]*[A-Za-z0-9\]])?$`)

// ValidateHost rejects a host that is unusable as a credential-store partition.
//
// The endpoint reaches us from --synq-endpoint, SYNQ_API_ENDPOINT, SYNQ_API_URL or
// a .env file, which is not always under the user's eye — synq-monitors reads .env
// from the working directory, so a cloned repository can set it. An endpoint of
// ".." parsed to a host of ".." and put the token file a directory above the
// store; on Windows a host containing a backslash escaped several levels, because
// filepath treats it as a separator there.
func ValidateHost(host string) error {
	switch {
	case host == "":
		return errors.New("endpoint has no host")
	case host == "." || host == "..":
		return fmt.Errorf("invalid endpoint host %q", host)
	case strings.ContainsAny(host, `/\`):
		return fmt.Errorf("invalid endpoint host %q: contains a path separator", host)
	case !hostPattern.MatchString(host):
		return fmt.Errorf("invalid endpoint host %q: not a hostname or IP address", host)
	}
	return nil
}

// Validate reports whether the target is usable.
func (t Target) Validate() error {
	if err := ValidateHost(t.Host); err != nil {
		return err
	}
	if t.Flow != "" && !hostPattern.MatchString(t.Flow) {
		// The flow is part of a filename (token-<flow>.json).
		return fmt.Errorf("invalid authorization flow %q", t.Flow)
	}
	return nil
}

// TargetForRegion resolves a named region to a Target.
func TargetForRegion(name string) (Target, error) {
	r, ok := LookupRegion(name)
	if !ok {
		return Target{}, fmt.Errorf("unknown region %q, expected one of %s", name, strings.Join(RegionNames(), ", "))
	}
	return TargetForEndpoint(r.APIEndpoint).withRegion(r.Name), nil
}

// TargetForEndpoint resolves an explicit host:port endpoint to a Target. When
// the endpoint matches a named region the region name is attached, so
// --synq-endpoint developer.synq.io:443 and --region eu land in the same store
// slot rather than two.
func TargetForEndpoint(endpoint string) Target {
	endpoint = normalizeEndpoint(endpoint)
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	t := Target{Endpoint: endpoint, Host: host}
	for _, r := range regions {
		if normalizeEndpoint(r.APIEndpoint) == endpoint {
			t.Region = r.Name
			break
		}
	}
	return t
}

func (t Target) withRegion(name string) Target {
	t.Region = name
	return t
}

// WithFlow returns a copy of the target bound to an authorize flow
// flavour. The flow gets its own token slot in the store.
func (t Target) WithFlow(flow string) Target {
	t.Flow = flow
	return t
}

// ResolveTarget picks a target from the region name and endpoint a CLI
// collected, in the order: explicit endpoint wins (the escape hatch for
// staging and self-hosted), then --region, then the default region.
func ResolveTarget(region, endpoint string) (Target, error) {
	if endpoint != "" {
		t := TargetForEndpoint(endpoint)
		if err := t.Validate(); err != nil {
			return Target{}, err
		}
		if region != "" {
			named, err := TargetForRegion(region)
			if err != nil {
				return Target{}, err
			}
			if named.Endpoint != t.Endpoint {
				return Target{}, fmt.Errorf(
					"--region %s is %s but an endpoint %s was also given; pass only one",
					region, named.Endpoint, t.Endpoint,
				)
			}
		}
		return t, nil
	}
	if region == "" {
		region = DefaultRegion
	}
	return TargetForRegion(region)
}

// normalizeEndpoint accepts the shapes a CLI or env var may carry — a bare
// host, a host:port, or a URL — and returns host:port. fe-app's per-region env
// files disagree on whether the scheme and port are present, so the CLIs
// tolerate both rather than requiring the user to know which.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	scheme := ""
	if i := strings.Index(endpoint, "://"); i >= 0 {
		scheme = strings.ToLower(endpoint[:i])
		endpoint = endpoint[i+3:]
	}
	endpoint = strings.TrimSuffix(endpoint, "/")
	if i := strings.IndexAny(endpoint, "/?#"); i >= 0 {
		endpoint = endpoint[:i]
	}
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	port := "443"
	if scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(endpoint, port)
}
