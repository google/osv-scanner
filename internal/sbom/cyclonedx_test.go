package sbom_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/sbom"
)

func runCycloneGetPackages(t *testing.T, bomFile string, want []sbom.Identifier) {
	t.Helper()

	f, err := os.Open(filepath.Join("fixtures", bomFile))
	if err != nil {
		t.Fatalf("Failed to read fixture file: %v", err)
	}
	defer f.Close()

	got := []sbom.Identifier{}
	callback := func(id sbom.Identifier) error {
		got = append(got, id)
		return nil
	}

	cdx := &sbom.CycloneDX{}
	err = cdx.GetPackages(f, callback)
	if err != nil {
		t.Errorf("GetPackages returned an error: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetPackages() returned an unexpected result (-want +got):\n%s", diff)
	}
}

func TestCycloneDXGetPackages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		bomFile     string
		identifiers []sbom.Identifier
	}{
		{
			bomFile: "cyclonedx.json",
			identifiers: []sbom.Identifier{
				{PURL: "pkg:maven/org.hdrhistogram/HdrHistogram@2.1.12"},
				{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0"},
			},
		},
		{
			bomFile:     "cyclonedx-empty.json",
			identifiers: []sbom.Identifier{},
		},
	}

	for _, tt := range tests {
		runCycloneGetPackages(t, tt.bomFile, tt.identifiers)
	}
}
