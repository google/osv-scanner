package datasource

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"deps.dev/util/maven"
	"deps.dev/util/semver"
	"golang.org/x/net/html/charset"
)

const MavenCentral = "https://repo.maven.apache.org/maven2"

var errAPIFailed = errors.New("API query failed")
var errUntrustedRegistry = errors.New("untrusted Maven registry URL")

// lookupHost is indirected so tests can stub DNS resolution.
var lookupHost = net.LookupHost

type MavenRegistryAPIClient struct {
	defaultRegistry MavenRegistry                  // The default registry that we are making requests
	registries      []MavenRegistry                // Additional registries specified to fetch projects
	registryAuths   map[string]*HTTPAuthentication // Authentication for the registries keyed by registry ID. From settings.xml

	// Cache fields
	mu             *sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	responses      *RequestCache[string, response]
}

type response struct {
	StatusCode int
	Body       []byte
}

type MavenRegistry struct {
	URL    string
	Parsed *url.URL

	// Information from pom.xml
	ID               string
	ReleasesEnabled  bool
	SnapshotsEnabled bool

	// TrustedForAuth indicates the registry URL is from a trusted source
	// (e.g. a user-supplied CLI flag) and is allowed to receive credentials
	// looked up from settings.xml. Registries sourced from parsed pom.xml
	// files must never set this, otherwise a hostile pom.xml can redirect
	// requests and steal the matching <server> credentials.
	TrustedForAuth bool
}

// validateUntrustedRegistryURL rejects URLs that either use a non-http(s)
// scheme or point at private/loopback/link-local/unspecified/multicast
// addresses. It is only applied to registries added from pom.xml files
// (via AddRegistry). The default registry passed to
// NewMavenRegistryAPIClient is intentionally exempt so enterprise users
// can still point osv-scanner at internal Artifactory/Nexus instances.
func validateUntrustedRegistryURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: nil URL", errUntrustedRegistry)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: scheme %q not allowed", errUntrustedRegistry, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: empty host", errUntrustedRegistry)
	}
	// Resolve and reject any address that is not publicly routable.
	addrs, err := lookupHost(host)
	if err != nil {
		return fmt.Errorf("%w: resolving %q: %w", errUntrustedRegistry, host, err)
	}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("%w: parsing resolved address %q: %w", errUntrustedRegistry, a, err)
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("%w: host %q resolves to non-public address %s", errUntrustedRegistry, host, a)
		}
	}

	return nil
}

func NewMavenRegistryAPIClient(registry MavenRegistry) (*MavenRegistryAPIClient, error) {
	if registry.URL == "" {
		registry.URL = MavenCentral
		registry.ID = "central"
	}
	u, err := url.Parse(registry.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Maven registry %s: %w", registry.URL, err)
	}
	registry.Parsed = u
	// The default registry is user-configured (CLI flag or library caller)
	// and is the only registry trusted to receive settings.xml credentials.
	registry.TrustedForAuth = true

	// TODO: allow for manual specification of settings files
	globalSettings := ParseMavenSettings(globalMavenSettingsFile())
	userSettings := ParseMavenSettings(userMavenSettingsFile())

	return &MavenRegistryAPIClient{
		// We assume only downloading releases is allowed on the default registry.
		defaultRegistry: registry,
		mu:              &sync.Mutex{},
		responses:       NewRequestCache[string, response](),
		registryAuths:   MakeMavenAuth(globalSettings, userSettings),
	}, nil
}

// WithoutRegistries makes MavenRegistryAPIClient including its cache but not registries.
func (m *MavenRegistryAPIClient) WithoutRegistries() *MavenRegistryAPIClient {
	return &MavenRegistryAPIClient{
		defaultRegistry: m.defaultRegistry,
		mu:              m.mu,
		cacheTimestamp:  m.cacheTimestamp,
		responses:       m.responses,
	}
}

// AddRegistry adds the given registry to the list of registries if it has not been added.
//
// Registries added through this path are treated as untrusted input: they
// typically originate from <repositories> entries in parsed pom.xml files,
// which an attacker can control. The URL is validated against the
// untrusted-registry policy (http(s) only, no private/loopback targets) and
// the TrustedForAuth flag is force-cleared so that credentials from
// settings.xml are never attached to requests made against these
// registries.
func (m *MavenRegistryAPIClient) AddRegistry(registry MavenRegistry) error {
	for _, reg := range m.registries {
		if reg.ID == registry.ID {
			return nil
		}
	}

	u, err := url.Parse(registry.URL)
	if err != nil {
		return err
	}

	if err := validateUntrustedRegistryURL(u); err != nil {
		return fmt.Errorf("refusing to add Maven registry %q: %w", registry.URL, err)
	}

	registry.Parsed = u
	// Credentials looked up from settings.xml must never flow to a
	// registry defined by untrusted pom.xml content.
	registry.TrustedForAuth = false
	m.registries = append(m.registries, registry)

	return nil
}

func (m *MavenRegistryAPIClient) GetRegistries() (registries []MavenRegistry) {
	return m.registries
}

// GetProject fetches a pom.xml specified by groupID, artifactID and version and parses it to maven.Project.
// Each registry in the list is tried until we find the project.
// For a snapshot version, version level metadata is used to find the extact version string.
// More about Maven Repository Metadata Model: https://maven.apache.org/ref/3.9.9/maven-repository-metadata/
// More about Maven Metadata: https://maven.apache.org/repositories/metadata.html
func (m *MavenRegistryAPIClient) GetProject(ctx context.Context, groupID, artifactID, version string) (maven.Project, error) {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		for _, registry := range append(m.registries, m.defaultRegistry) {
			if !registry.ReleasesEnabled {
				continue
			}
			project, err := m.getProject(ctx, registry, groupID, artifactID, version, "")
			if err == nil {
				return project, nil
			}
		}

		return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s", groupID, artifactID, version)
	}

	for _, registry := range append(m.registries, m.defaultRegistry) {
		// Fetch version metadata for snapshot versions from the registries enabling that.
		if !registry.SnapshotsEnabled {
			continue
		}
		metadata, err := m.getVersionMetadata(ctx, registry, groupID, artifactID, version)
		if err != nil {
			continue
		}

		snapshot := ""
		for _, sv := range metadata.Versioning.SnapshotVersions {
			if sv.Extension == "pom" {
				// We only look for pom.xml for project metadata.
				snapshot = string(sv.Value)
				break
			}
		}

		project, err := m.getProject(ctx, registry, groupID, artifactID, version, snapshot)
		if err == nil {
			return project, nil
		}
	}

	return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s", groupID, artifactID, version)
}

// GetVersions returns the list of available versions of a Maven package specified by groupID and artifactID.
// Versions found in all registries are unioned, then sorted by semver.
func (m *MavenRegistryAPIClient) GetVersions(ctx context.Context, groupID, artifactID string) ([]maven.String, error) {
	var versions []maven.String
	for _, registry := range append(m.registries, m.defaultRegistry) {
		metadata, err := m.getArtifactMetadata(ctx, registry, groupID, artifactID)
		if err != nil {
			continue
		}
		versions = append(versions, metadata.Versioning.Versions...)
	}
	slices.SortFunc(versions, func(a, b maven.String) int { return semver.Maven.Compare(string(a), string(b)) })

	return slices.Compact(versions), nil
}

// getProject fetches a pom.xml specified by groupID, artifactID and version and parses it to maven.Project.
// For snapshot versions, the exact version value is specified by snapshot.
func (m *MavenRegistryAPIClient) getProject(ctx context.Context, registry MavenRegistry, groupID, artifactID, version, snapshot string) (maven.Project, error) {
	if snapshot == "" {
		snapshot = version
	}
	u := registry.Parsed.JoinPath(strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, snapshot)).String()

	var project maven.Project
	if err := m.get(ctx, m.authFor(registry), u, &project); err != nil {
		return maven.Project{}, err
	}

	return project, nil
}

// getVersionMetadata fetches a version level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getVersionMetadata(ctx context.Context, registry MavenRegistry, groupID, artifactID, version string) (maven.Metadata, error) {
	u := registry.Parsed.JoinPath(strings.ReplaceAll(groupID, ".", "/"), artifactID, version, "maven-metadata.xml").String()

	var metadata maven.Metadata
	if err := m.get(ctx, m.authFor(registry), u, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	return metadata, nil
}

// GetArtifactMetadata fetches an artifact level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getArtifactMetadata(ctx context.Context, registry MavenRegistry, groupID, artifactID string) (maven.Metadata, error) {
	u := registry.Parsed.JoinPath(strings.ReplaceAll(groupID, ".", "/"), artifactID, "maven-metadata.xml").String()

	var metadata maven.Metadata
	if err := m.get(ctx, m.authFor(registry), u, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	return metadata, nil
}

// authFor returns the configured HTTP credentials for a registry only if
// the registry was marked trusted by NewMavenRegistryAPIClient. Registries
// added from parsed pom.xml files get nil, which makes auth.Get perform an
// unauthenticated request.
func (m *MavenRegistryAPIClient) authFor(registry MavenRegistry) *HTTPAuthentication {
	if !registry.TrustedForAuth {
		return nil
	}

	return m.registryAuths[registry.ID]
}

func (m *MavenRegistryAPIClient) get(ctx context.Context, auth *HTTPAuthentication, apiURL string, dst any) error {
	resp, err := m.responses.Get(apiURL, func() (response, error) {
		resp, err := auth.Get(ctx, http.DefaultClient, apiURL)
		if err != nil {
			return response{}, fmt.Errorf("%w: Maven registry query failed: %w", errAPIFailed, err)
		}
		defer resp.Body.Close()

		if !slices.Contains([]int{http.StatusOK, http.StatusNotFound, http.StatusUnauthorized}, resp.StatusCode) {
			// Only cache responses with Status OK, NotFound, or Unauthorized
			return response{}, fmt.Errorf("%w: Maven registry query status: %d", errAPIFailed, resp.StatusCode)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return response{}, fmt.Errorf("failed to read body: %w", err)
		}

		return response{StatusCode: resp.StatusCode, Body: b}, nil
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: Maven registry query status: %d", errAPIFailed, resp.StatusCode)
	}

	return NewMavenDecoder(bytes.NewReader(resp.Body)).Decode(dst)
}

// NewMavenDecoder returns an xml decoder with CharsetReader and Entity set.
func NewMavenDecoder(reader io.Reader) *xml.Decoder {
	decoder := xml.NewDecoder(reader)
	// Set charset reader for conversion from non-UTF-8 charset into UTF-8.
	decoder.CharsetReader = charset.NewReaderLabel
	// Set HTML entity map for translation between non-standard entity names
	// and string replacements.
	decoder.Entity = xml.HTMLEntity

	return decoder
}
