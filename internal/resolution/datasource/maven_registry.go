package datasource

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"deps.dev/util/maven"
)

const MavenCentral = "https://repo.maven.apache.org/maven2"

type MavenRegistryAPIClient struct {
	registry string // Base URL of the registry that we are making requests
}

func NewMavenRegistryAPIClient(registry string) *MavenRegistryAPIClient {
	return &MavenRegistryAPIClient{registry: registry}
}

var errAPIFailed = errors.New("API query failed")

func (m *MavenRegistryAPIClient) GetProject(ctx context.Context, groupID, artifactID, version string) (maven.Project, error) {
	u, err := url.JoinPath(m.registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, version))
	if err != nil {
		return maven.Project{}, fmt.Errorf("failed to join path: %w", err)
	}

	var proj maven.Project
	if err := get(ctx, u, &proj); err != nil {
		return maven.Project{}, err
	}

	return proj, nil
}

func (m *MavenRegistryAPIClient) GetMetadata(ctx context.Context, groupID, artifactID string) (maven.Metadata, error) {
	u, err := url.JoinPath(m.registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, "maven-metadata.xml")
	if err != nil {
		return maven.Metadata{}, fmt.Errorf("failed to join path: %w", err)
	}

	var metadata maven.Metadata
	if err := get(ctx, u, &metadata); err != nil {
		return maven.Metadata{}, err
	}

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

	return xml.NewDecoder(resp.Body).Decode(dst)
}
