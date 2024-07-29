package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestNuGetLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig sharedtesthelpers.ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "packages.lock.json",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/packages.lock.json",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/packages.lock.json/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/packages.lock.json.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.packages.lock.json",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.NuGetLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestNuGetLockExtractor_Extract_invalidVersion(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid version",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/empty.v0.json",
			},
			WantErrContaining: "unsupported lock file version 0",
			WantInventory:     []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.NuGetLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
