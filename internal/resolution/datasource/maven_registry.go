package datasource

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"deps.dev/util/maven"
	"github.com/google/osv-scanner/pkg/osvscanner"
)

const MavenCentral = "https://repo.maven.apache.org/maven2"

type MavenRegistryAPIClient struct {
	Registry string // Base URL of the registry that we are making requests
}

func NewMavenRegistryAPIClient() (*MavenRegistryAPIClient, error) {
	return &MavenRegistryAPIClient{
		Registry: MavenCentral,
	}, nil
}

func (m *MavenRegistryAPIClient) GetProject(ctx context.Context, groupID, artifactID, version string) (maven.Project, error) {
	url, err := url.JoinPath(m.Registry, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, version))
	if err != nil {
		return maven.Project{}, fmt.Errorf("failed to join path: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return maven.Project{}, fmt.Errorf("failed to make new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return maven.Project{}, fmt.Errorf("%w: Maven registry query failed: %w", osvscanner.ErrAPIFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return maven.Project{}, fmt.Errorf("%w: Maven registry query status: %s", osvscanner.ErrAPIFailed, resp.Status)
	}

	var proj maven.Project
	if err := xml.NewDecoder(resp.Body).Decode(&proj); err != nil {
		return maven.Project{}, fmt.Errorf("failed to decode Maven project: %w", err)
	}

	return proj, nil
}
