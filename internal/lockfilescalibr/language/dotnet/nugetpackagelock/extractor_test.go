package nugetpackagelock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/dotnet/nugetpackagelock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "packages.lock.json",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/packages.lock.json",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/packages.lock.json/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/packages.lock.json.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.packages.lock.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := nugetpackagelock.Extractor{}
			got := e.FileRequired(tt.inputPath, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract_invalidVersion(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:              "invalid version",
			inputPath:         "testdata/empty.v0.json",
			WantErrContaining: "unsupported lock file version 0",
			WantInventory:     []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := nugetpackagelock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
