// Package testutility provides utility functions for tests.
package testutility

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// load returns the contents of the fixture file after applying any replacements if on Windows
func load(t *testing.T, path string, windowsReplacements map[string]string) []byte {
	t.Helper()

	var file []byte
	var err error

	file, err = os.ReadFile(path)

	if err != nil {
		t.Fatalf("Failed to open fixture: %s", err)
	}

	return []byte(applyWindowsReplacements(string(file), windowsReplacements))
}

// LoadJSONFixture returns the contents of the fixture file parsed as JSON
func LoadJSONFixture[V any](t *testing.T, path string) V {
	t.Helper()

	return LoadJSONFixtureWithWindowsReplacements[V](t, path, map[string]string{})
}

// LoadJSONFixtureWithWindowsReplacements returns the contents of the fixture
// file parsed as JSON after applying any replacements if running on Windows
func LoadJSONFixtureWithWindowsReplacements[V any](
	t *testing.T,
	path string,
	replacements map[string]string,
) V {
	t.Helper()

	file := load(t, path, replacements)

	var elem V
	err := json.Unmarshal(file, &elem)
	if err != nil {
		t.Fatalf("Failed to unmarshal val: %s", err)
	}

	return elem
}

// LoadVulnMapFixture returns the contents of the fixture file parsed as a map of vulnerability IDs to vulnerabilities
func LoadVulnMapFixture(t *testing.T, path string) map[string]*osvschema.Vulnerability {
	t.Helper()

	file := load(t, path, map[string]string{})

	var raw map[string]json.RawMessage
	err := json.Unmarshal(file, &raw)
	if err != nil {
		t.Fatalf("Failed to unmarshal val: %s", err)
	}

	vulns := make(map[string]*osvschema.Vulnerability)
	for id, rawVuln := range raw {
		vuln := &osvschema.Vulnerability{}
		if err := protojson.Unmarshal(rawVuln, vuln); err != nil {
			t.Fatalf("Failed to unmarshal vuln %s: %s", id, err)
		}
		vulns[id] = vuln
	}

	return vulns
}
