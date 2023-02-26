package govulncheckshim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_RunGoVulnCheck(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("fixtures")
	if err != nil {
		t.Errorf("failed to read fixtures dir: %v", err)
	}

	vulns := []models.Vulnerability{}
	for _, de := range entries {
		if !de.Type().IsRegular() {
			continue
		}

		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}

		file, err := os.Open(filepath.Join("fixtures", de.Name()))
		if err != nil {
			t.Errorf("failed to open fixture vuln files: %v", err)
		}

		newVuln := models.Vulnerability{}
		err = json.NewDecoder(file).Decode(&newVuln)
		if err != nil {
			t.Errorf("failed to decode fixture vuln files: %v", err)
		}
		vulns = append(vulns, newVuln)
	}

	res, err := RunGoVulnCheck("fixtures/test-project", vulns)
	if err != nil {
		t.Errorf("failed to run RunGoVulnCheck: %v", err)
	}

	res.Vulns[0].Modules[0].Packages[0].CallStacks[0].Frames[0].Position.Filename = "<Any value>"
	testutility.AssertMatchFixtureJSON(t, "fixtures/snapshots/govulncheckshim_test.json", res)
}
