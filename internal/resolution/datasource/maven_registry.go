package datasource

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"deps.dev/util/maven"
	"golang.org/x/net/html/charset"
)

const MavenCentral = "https://repo.maven.apache.org/maven2"

type MavenRegistryAPIClient struct {
	registry string // Base URL of the registry that we are making requests

	// Cache fields
	mu             sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	projects       map[string]maven.Project
	metadata       map[string]maven.Metadata
}

func NewMavenRegistryAPIClient(registry string) *MavenRegistryAPIClient {
	return &MavenRegistryAPIClient{
		registry: registry,
		projects: make(map[string]maven.Project),
		metadata: make(map[string]maven.Metadata),
	}
}

var errAPIFailed = errors.New("API query failed")

// GetProject fetches a pom.xml specified by groupID, artifactID and version and parses it to maven.Project.
// For a snapshot version, version level metadata is used to find the extact version string.
// More about Maven Repository Metadata Model: https://maven.apache.org/ref/3.9.9/maven-repository-metadata/
// More about Maven Metadata: https://maven.apache.org/repositories/metadata.html
func (m *MavenRegistryAPIClient) GetProject(ctx context.Context, groupID, artifactID, version string) (maven.Project, error) {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return m.getProject(ctx, groupID, artifactID, version, "")
	}

	// Fetch version metadata for snapshot versions.
	metadata, err := m.getVersionMetadata(ctx, groupID, artifactID, version)
	if err != nil {
		return maven.Project{}, err
	}

	snapshot := ""
	for _, sv := range metadata.Versioning.SnapshotVersions {
		if sv.Extension == "pom" {
			// We only look for pom.xml for project metadata.
			snapshot = string(sv.Value)
			break
		}
	}

	return m.getProject(ctx, groupID, artifactID, version, snapshot)
}

// getProject fetches a pom.xml specified by groupID, artifactID and version and parses it to maven.Project.
// For snapshot versions, the exact version value is specified by snapshot.
func (m *MavenRegistryAPIClient) getProject(ctx context.Context, groupID, artifactID, version, snapshot string) (maven.Project, error) {
	if snapshot == "" {
		snapshot = version
	}
	u, err := url.JoinPath(m.registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, snapshot))
	if err != nil {
		return maven.Project{}, fmt.Errorf("failed to join path: %w", err)
	}

	m.mu.Lock()
	proj, ok := m.projects[u]
	m.mu.Unlock()
	if ok {
		return proj, nil
	}

	if err := get(ctx, u, &proj); err != nil {
		return maven.Project{}, err
	}

	m.mu.Lock()
	m.projects[u] = proj
	m.mu.Unlock()

	return proj, nil
}

// getVersionMetadata fetches a version level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getVersionMetadata(ctx context.Context, groupID, artifactID, version string) (maven.Metadata, error) {
	u, err := url.JoinPath(m.registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, "maven-metadata.xml")
	if err != nil {
		return maven.Metadata{}, fmt.Errorf("failed to join path: %w", err)
	}

	m.mu.Lock()
	metadata, ok := m.metadata[u]
	m.mu.Unlock()
	if ok {
		return metadata, nil
	}

	if err := get(ctx, u, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	m.mu.Lock()
	m.metadata[u] = metadata
	m.mu.Unlock()

	return metadata, nil
}

// GetArtifactMetadata fetches an artifact level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) GetArtifactMetadata(ctx context.Context, groupID, artifactID string) (maven.Metadata, error) {
	u, err := url.JoinPath(m.registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, "maven-metadata.xml")
	if err != nil {
		return maven.Metadata{}, fmt.Errorf("failed to join path: %w", err)
	}

	m.mu.Lock()
	metadata, ok := m.metadata[u]
	m.mu.Unlock()
	if ok {
		return metadata, nil
	}

	if err := get(ctx, u, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	m.mu.Lock()
	m.metadata[u] = metadata
	m.mu.Unlock()

	return metadata, nil
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
