package vendored_test

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"osv.dev/bindings/go/osvdev"
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
			name:         "Empty_path",
			path:         filepath.FromSlash(""),
			isDir:        false,
			wantRequired: false,
		},
		{
			name:         "single_directory_not_under_vendor_dir",
			path:         filepath.FromSlash("test_dir/"),
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "vendored_dir_itself_should_not_match",
			path:         filepath.FromSlash("vendor/"),
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "vendored_dir_itself_should_not_match_(no_trailing_slash)",
			path:         filepath.FromSlash("vendor"),
			isDir:        true,
			wantRequired: false,
		},
		{
			name:         "vendored_dir_with_child_non_directory_should_not_match",
			path:         filepath.FromSlash("vendor/abcd"),
			isDir:        false,
			wantRequired: false,
		},
		{
			name:         "vendored_dir_with_child_directory_should_match",
			path:         filepath.FromSlash("vendor/abcd/"),
			isDir:        true,
			wantRequired: true,
		},
		{
			name:         "vendored_dir_with_child_directory_should_match",
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
	cwd := testutility.GetCurrentWorkingDirectory(t)

	tests := []extracttest.TestTableEntry{
		{
			Name: "zlib_test",
			InputConfig: extracttest.ScanInputMockConfig{
				Path:         "testdata/thirdparty/zlib",
				FakeScanRoot: cwd,
			},
			WantPackages: []*extractor.Package{
				{
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851",
					},
					Location: extractor.LocationFromPath("testdata/thirdparty/zlib"),
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
