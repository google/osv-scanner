package datasource

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
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

type MavenRegistryAPIClient struct {
	defaultRegistry string // Base URL of the default registry that we are making requests
	// TODO: disable fetching snapshot if specified in pom.xml
	registries []string // URLs of the registries to fetch projects

	// Cache fields
	mu             *sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	projects       *RequestCache[string, maven.Project]
	metadata       *RequestCache[string, maven.Metadata]
}

func NewMavenRegistryAPIClient(registry string) (*MavenRegistryAPIClient, error) {
	if registry == "" {
		registry = MavenCentral
	} else if _, err := url.Parse(registry); err != nil {
		return nil, fmt.Errorf("invalid Maven registry %s: %w", registry, err)
	}

	return &MavenRegistryAPIClient{
		defaultRegistry: registry,
		mu:              &sync.Mutex{},
		projects:        NewRequestCache[string, maven.Project](),
		metadata:        NewRequestCache[string, maven.Metadata](),
	}, nil
}

// CloneWithoutRegistries copies MavenRegistryAPIClient including its cache but not registries.
func (m *MavenRegistryAPIClient) CloneWithoutRegistries() *MavenRegistryAPIClient {
	return &MavenRegistryAPIClient{
		defaultRegistry: m.defaultRegistry,
		mu:              m.mu,
		cacheTimestamp:  m.cacheTimestamp,
		projects:        m.projects,
		metadata:        m.metadata,
	}
}

// Add adds the given registry to the list of registries if it has not been added.
func (m *MavenRegistryAPIClient) AddRegistry(registry string) error {
	if slices.Contains(m.registries, registry) {
		return nil
	}

	if _, err := url.Parse(registry); err != nil {
		return err
	}
	m.registries = append(m.registries, registry)

	return nil
}

func (m *MavenRegistryAPIClient) GetRegistries() []string {
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
			project, err := m.getProject(ctx, registry, groupID, artifactID, version, "")
			if err == nil {
				return project, nil
			}
		}

		return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s", groupID, artifactID, version)
	}

	for _, registry := range append(m.registries, m.defaultRegistry) {
		// Fetch version metadata for snapshot versions.
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
func (m *MavenRegistryAPIClient) getProject(ctx context.Context, registry, groupID, artifactID, version, snapshot string) (maven.Project, error) {
	if snapshot == "" {
		snapshot = version
	}
	u, err := url.JoinPath(registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, snapshot))
	if err != nil {
		return maven.Project{}, fmt.Errorf("failed to join path: %w", err)
	}

	return m.projects.Get(u, func() (maven.Project, error) {
		var proj maven.Project
		if err := get(ctx, u, &proj); err != nil {
			return maven.Project{}, err
		}

		return proj, nil
	})
}

// getVersionMetadata fetches a version level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getVersionMetadata(ctx context.Context, registry, groupID, artifactID, version string) (maven.Metadata, error) {
	u, err := url.JoinPath(registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, "maven-metadata.xml")
	if err != nil {
		return maven.Metadata{}, fmt.Errorf("failed to join path: %w", err)
	}

	return m.metadata.Get(u, func() (maven.Metadata, error) {
		var metadata maven.Metadata
		if err := get(ctx, u, &metadata); err != nil {
			return maven.Metadata{}, err
		}

		return metadata, nil
	})
}

// GetArtifactMetadata fetches an artifact level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getArtifactMetadata(ctx context.Context, registry, groupID, artifactID string) (maven.Metadata, error) {
	u, err := url.JoinPath(registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, "maven-metadata.xml")
	if err != nil {
		return maven.Metadata{}, fmt.Errorf("failed to join path: %w", err)
	}

	return m.metadata.Get(u, func() (maven.Metadata, error) {
		var metadata maven.Metadata
		if err := get(ctx, u, &metadata); err != nil {
			return maven.Metadata{}, err
		}

		return metadata, nil
	})
}

func get(ctx context.Context, url string, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to make new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: Maven registry query failed: %w", errAPIFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: Maven registry query status: %s", errAPIFailed, resp.Status)
	}

	d := xml.NewDecoder(resp.Body)
	// Set charset reader for conversion from non-UTF-8 charset into UTF-8.
	d.CharsetReader = charset.NewReaderLabel
	// Set HTML entity map for translation between non-standard entity names
	// and string replacements.
	d.Entity = xml.HTMLEntity

	return d.Decode(dst)
}
