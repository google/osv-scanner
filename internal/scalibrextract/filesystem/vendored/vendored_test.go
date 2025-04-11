package vendored_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scanner/v2/internal/osvdev"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		path         string
		isDir        bool
		wantRequired bool
	}{
		{
			name:         "Empty path",
			path:         filepath.FromSlash(""),
			isDir:        false,
			wantRequired: false,
		},
		{
			name:         "single directory not under vendor dir",
			path:         filepath.FromSlash("test_dir/"),
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "vendored dir itself should not match",
			path:         filepath.FromSlash("vendor/"),
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "vendored dir itself should not match (no trailing slash)",
			path:         filepath.FromSlash("vendor"),
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "vendored dir with child non directory should not match",
			path:         filepath.FromSlash("vendor/abcd"),
			isDir:        false,
			wantRequired: false,
		},
		{
			name:         "vendored dir with child directory should match",
			path:         filepath.FromSlash("vendor/abcd/"),
			isDir:        true,
			wantRequired: true,
		},
		{
			name:         "vendored dir with child directory should match",
			path:         filepath.FromSlash("thirdparty/efgh/"),
			isDir:        true,
			wantRequired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extr := vendored.Extractor{}

			permission := fs.ModePerm
			if tt.isDir {
				permission = fs.ModePerm | fs.ModeDir
			}
			isRequired := extr.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: permission,
				FileSize: 1000,
			}))

			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		// TODO: Reenable when #657 is resolved.
		testutility.Skip(t, "Temporarily disabled until #657 is resolved")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tests := []extracttest.TestTableEntry{
		{
			Name: "zlib test",
			InputConfig: extracttest.ScanInputMockConfig{
				Path:         "testdata/thirdparty/zlib",
				FakeScanRoot: cwd,
			},
			WantPackages: []*extractor.Package{
				{
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851",
					},
					Locations: []string{"testdata/thirdparty/zlib"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := vendored.Extractor{
				OSVClient: osvdev.DefaultClient(),
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantPackages, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
