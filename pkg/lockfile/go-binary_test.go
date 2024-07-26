package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGoBinaryExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "full permission file",
			inputConfig: ScanInputMockConfig{
				path: "some_path",
				fakeFileInfo: &FakeFileInfo{
					FileMode: 0777,
					FileSize: 100,
				},
			},
			want: true,
		},
		{
			name: "no executable file",
			inputConfig: ScanInputMockConfig{
				path: "some_path_not_executable",
				fakeFileInfo: &FakeFileInfo{
					FileMode: 0666,
					FileSize: 100,
				},
			},
			want: false,
		},
		{
			name: "only owner executable file",
			inputConfig: ScanInputMockConfig{
				path: "some_path_not_executable",
				fakeFileInfo: &FakeFileInfo{
					FileMode: 0700,
					FileSize: 100,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GoBinaryExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestGoBinaryExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/binaries/just-go",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "stdlib",
					Version:   "1.21.10",
					Locations: []string{"fixtures/go/binaries/just-go"},
				},
			},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/binaries/has-one-dep",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "stdlib",
					Version:   "1.21.10",
					Locations: []string{"fixtures/go/binaries/has-one-dep"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.4.0",
					Locations: []string{"fixtures/go/binaries/has-one-dep"},
				},
			},
		},
		{
			name: "not a go binary",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/one-package.mod",
			},
			wantErrContaining: "file format is incompatible",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GoBinaryExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

// func TestExtractGoBinary_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	file, err := lockfile.OpenLocalDepFile("fixtures/go/binaries/just-go")
// 	if err != nil {
// 		t.Fatalf("could not open file %v", err)
// 	}

// 	packages, err := lockfile.GoBinaryExtractor{}.Extract(file)
// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "stdlib",
// 			Version:   "1.21.10",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestExtractGoBinary_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	file, err := lockfile.OpenLocalDepFile("fixtures/go/binaries/has-one-dep")
// 	if err != nil {
// 		t.Fatalf("could not open file %v", err)
// 	}

// 	packages, err := lockfile.GoBinaryExtractor{}.Extract(file)
// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "stdlib",
// 			Version:   "1.21.10",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "github.com/BurntSushi/toml",
// 			Version:   "1.4.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestExtractGoBinary_NotAGoBinary(t *testing.T) {
// 	t.Parallel()

// 	file, err := lockfile.OpenLocalDepFile("fixtures/go/one-package.mod")
// 	if err != nil {
// 		t.Fatalf("could not open file %v", err)
// 	}

// 	packages, err := lockfile.GoBinaryExtractor{}.Extract(file)
// 	if err == nil {
// 		t.Errorf("did not get expected error when extracting")
// 	}

// 	if len(packages) != 0 {
// 		t.Errorf("packages not empty")
// 	}
// }
