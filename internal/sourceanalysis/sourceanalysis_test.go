package sourceanalysis

import (
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestRun_SkipsCallAnalysisWhenOffline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source models.SourceInfo
	}{
		{
			name: "go",
			source: models.SourceInfo{
				Path: "testdata/go-integration/test-project/go.mod",
				Type: models.SourceTypeProjectPackage,
			},
		},
		{
			name: "rust",
			source: models.SourceInfo{
				Path: "testdata/rust/rust-project/Cargo.lock",
				Type: models.SourceTypeProjectPackage,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgs := []models.PackageVulns{
				{
					Package: models.PackageInfo{Name: "example", Version: "1.0.0"},
					Groups:  []models.GroupInfo{{IDs: []string{"OSV-1"}}},
				},
			}

			Run(tt.source, pkgs, map[string]bool{"go": true, "rust": true}, true)

			// running call analysis always initializes the analysis map of each group,
			// so it should be left untouched if the analysis was skipped
			for _, pkg := range pkgs {
				for _, group := range pkg.Groups {
					if group.ExperimentalAnalysis != nil {
						t.Errorf("expected call analysis to be skipped, but got %v", group.ExperimentalAnalysis)
					}
				}
			}
		})
	}
}
