package gitrepo_test

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/vcs/gitrepo"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []extracttest.TestTableEntry{
		{
			Name: "Not a git dir",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/example-not-git",
			},
			WantErr: extracttest.ContainsErrStr{Str: "repository does not exist"},
		},
		{
			Name: "example git",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/example-git",
			},
			WantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/example-git"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "862ac4bd2703b622e85f29f55a2fd8cd6caf8182",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := gitrepo.Extractor{}

			err := os.Rename(path.Join(tt.InputConfig.Path, "git-hidden"), path.Join(tt.InputConfig.Path, ".git"))
			if err != nil {
				t.Errorf("can't find git-hidden folder")
			}

			defer func() {
				err = os.Rename(path.Join(tt.InputConfig.Path, ".git"), path.Join(tt.InputConfig.Path, "git-hidden"))
				if err != nil {
					t.Fatalf("failed to restore .git to original git-hidden: %v", err)
				}
			}()

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
