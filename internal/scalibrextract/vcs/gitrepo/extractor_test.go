package gitrepo_test

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []extracttest.TestTableEntry{
		{
			Name: "Not a git dir",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/example-not-git/.git",
			},
			WantErr: extracttest.ContainsErrStr{Str: "repository does not exist"},
		},
		{
			Name: "example git",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/example-git/.git",
			},
			WantPackages: []*extractor.Package{
				{
					Locations: []string{"testdata/example-git/.git"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "862ac4bd2703b622e85f29f55a2fd8cd6caf8182",
					},
				},
			},
		},
		{
			Name: "Clean git repository with no commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/example-clean/.git",
			},
			WantPackages: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := gitrepo.Extractor{
				IncludeRootGit: true,
			}
			parent := filepath.Dir(tt.InputConfig.Path)
			err := os.Rename(path.Join(parent, "git-hidden"), path.Join(parent, ".git"))
			if err != nil {
				t.Errorf("can't find git-hidden folder")
			}

			defer func() {
				err = os.Rename(path.Join(parent, ".git"), path.Join(parent, "git-hidden"))
				if err != nil {
					t.Fatalf("failed to restore .git to original git-hidden: %v", err)
				}
			}()

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantPackages, got.Packages, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
