// Package clienttest provides a mock resolution client for testing.
package clienttest

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/schema"
	"github.com/goccy/go-yaml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/resolution/client"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

type ResolutionUniverse struct {
	System string `yaml:"system"`
	Schema string `yaml:"schema"`
}

type VulnerabilityMatcher struct {
	Vulns []*osvschema.Vulnerability `json:"vulns"`
}

// UnmarshalJSON unmarshals the mock vulns. The Vulnerability field is a proto
// message, so it needs to be unmarshaled with protojson.
func (vm *VulnerabilityMatcher) UnmarshalJSON(data []byte) error {
	var raw map[string][]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, v := range raw["vulns"] {
		if string(v) == "null" {
			vm.Vulns = append(vm.Vulns, nil)
			continue
		}
		vuln := &osvschema.Vulnerability{}
		if err := protojson.Unmarshal(v, vuln); err != nil {
			return err
		}
		vm.Vulns = append(vm.Vulns, vuln)
	}

	return nil
}

func (vm VulnerabilityMatcher) MatchVulnerabilities(_ context.Context, invs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	result := make([][]*osvschema.Vulnerability, len(invs))
	for i, inv := range invs {
		result[i] = localmatcher.VulnerabilitiesAffectingPackage(vm.Vulns, imodels.FromInventory(inv))
	}

	return result, nil
}

type mockDependencyClient struct {
	*resolve.LocalClient
}

func (mdc mockDependencyClient) LoadCache(string) error                  { return nil }
func (mdc mockDependencyClient) WriteCache(string) error                 { return nil }
func (mdc mockDependencyClient) AddRegistries(_ []client.Registry) error { return nil }

func NewMockResolutionClient(t *testing.T, universeYaml, vulnJSON string) client.ResolutionClient {
	t.Helper()

	f, err := os.Open(vulnJSON)
	if err != nil {
		t.Fatalf("failed reading mock vulnerability file: %v", err)
	}

	var vm VulnerabilityMatcher
	if err := json.NewDecoder(f).Decode(&vm); err != nil {
		t.Fatalf("failed decoding mock vulns: %v", err)
	}

	cl := client.ResolutionClient{
		VulnerabilityMatcher: vm,
	}

	f, err = os.Open(universeYaml)
	if err != nil {
		t.Fatalf("failed opening mock universe: %v", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)

	var universe ResolutionUniverse
	if err := dec.Decode(&universe); err != nil {
		t.Fatalf("failed decoding mock universe: %v", err)
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
