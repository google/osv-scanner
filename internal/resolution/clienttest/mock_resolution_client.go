package clienttest

import (
	"os"
	"strings"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/schema"
	"github.com/google/osv-scanner/internal/resolution/client"
	"github.com/google/osv-scanner/internal/resolution/util"
	"github.com/google/osv-scanner/internal/utility/vulns"
	"github.com/google/osv-scanner/pkg/models"
	"gopkg.in/yaml.v3"
)

type ResolutionUniverse struct {
	System string                 `yaml:"system"`
	Schema string                 `yaml:"schema"`
	Vulns  []models.Vulnerability `yaml:"vulns"`
}

type mockVulnerabilityClient []models.Vulnerability

func (mvc mockVulnerabilityClient) FindVulns(g *resolve.Graph) ([]models.Vulnerabilities, error) {
	result := make([]models.Vulnerabilities, len(g.Nodes))
	for i, n := range g.Nodes {
		if i == 0 {
			continue // skip root node
		}
		for _, v := range mvc {
			if vulns.IsAffected(v, util.VKToPackageDetails(n.Version)) {
				result[i] = append(result[i], v)
			}
		}
	}

	return result, nil
}

type mockDependencyClient struct {
	*resolve.LocalClient
}

func (mdc mockDependencyClient) LoadCache(string) error                  { return nil }
func (mdc mockDependencyClient) WriteCache(string) error                 { return nil }
func (mdc mockDependencyClient) AddRegistries(_ []client.Registry) error { return nil }

func NewMockResolutionClient(t *testing.T, universeYAML string) client.ResolutionClient {
	t.Helper()
	f, err := os.Open(universeYAML)
	if err != nil {
		t.Fatalf("failed opening mock universe: %v", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)

	var universe ResolutionUniverse
	if err := dec.Decode(&universe); err != nil {
		t.Fatalf("failed decoding mock universe: %v", err)
	}

	cl := client.ResolutionClient{
		VulnerabilityClient: mockVulnerabilityClient(universe.Vulns),
	}

	var sys resolve.System
	switch strings.ToLower(universe.System) {
	case "npm":
		sys = resolve.NPM
	case "maven":
		sys = resolve.Maven
	default:
		t.Fatalf("unknown ecosystem in universe: %s", universe.System)
	}

	// schema needs a strict tab indentation, which is awkward to do within the YAML.
	// Replace double space from yaml with single tab
	universe.Schema = strings.ReplaceAll(universe.Schema, "  ", "\t")
	sch, err := schema.New(universe.Schema, sys)
	if err != nil {
		t.Fatalf("failed parsing schema: %v", err)
	}

	cl.DependencyClient = mockDependencyClient{sch.NewClient()}

	return cl
}
