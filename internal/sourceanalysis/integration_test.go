package sourceanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var fixturesDir = "integration/fixtures-go"

func Test_runGovulncheck(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Errorf("failed to read fixtures dir: %v", err)
	}

	vulns := []osvschema.Vulnerability{}
	for _, de := range entries {
		if !de.Type().IsRegular() {
			continue
		}

		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}

		fn := filepath.Join(fixturesDir, de.Name())
		file, err := os.Open(fn)
		if err != nil {
			t.Errorf("failed to open fixture vuln files: %v", err)
		}

		newVuln := osvschema.Vulnerability{}
		err = json.NewDecoder(file).Decode(&newVuln)
		if err != nil {
			t.Errorf("failed to decode fixture vuln file (%q): %v", fn, err)
		}
		vulns = append(vulns, newVuln)
	}

	res, err := runGovulncheck(filepath.Join(fixturesDir, "test-project"), vulns, "1.19")
	if err != nil {
		t.Errorf("failed to run RunGoVulnCheck: %v", err)
	}

	res["GO-2023-1558"][2].Trace[0].Position.Filename = "<Any value>"
	res["GO-2023-1558"][2].Trace[1].Position.Filename = "<Any value>"
	res["GO-2023-1558"][2].Trace[0].Position.Offset = -1
	res["GO-2023-1558"][2].Trace[1].Position.Offset = -1

	for _, traceItem := range res["GO-2023-2382"][2].Trace {
		traceItem.Position.Filename = "<Any value>"
		traceItem.Position.Offset = -1
		traceItem.Position.Line = -1 // This number differs between go versions

		if traceItem.Function == "ListenAndServe" && traceItem.Receiver == "*Server" {
			traceItem.Position.Column = -1 // This number differs between go versions
		}
	}

	testutility.NewSnapshot().MatchJSON(t, res)
}
