package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestCargoLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig sharedtesthelpers.ScanInputMockConfig
		want        bool
	}{
		{
			name: "Empty path",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "Cargo.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/Cargo.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/Cargo.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/Cargo.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.Cargo.lock",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.CargoLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestCargoLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "Invalid toml",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/cargo/not-toml.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/cargo/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/cargo/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/one-package.lock"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/cargo/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/two-packages.lock"},
				},
				{
					Name:      "syn",
					Version:   "1.0.73",
					Locations: []string{"fixtures/cargo/two-packages.lock"},
				},
			},
		},
		{
			Name: "two packages with local",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/cargo/two-packages-with-local.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/two-packages-with-local.lock"},
				},
				{
					Name:      "local-rust-pkg",
					Version:   "0.1.0",
					Locations: []string{"fixtures/cargo/two-packages-with-local.lock"},
				},
			},
		},
		{
			Name: "package with build string",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/cargo/package-with-build-string.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wasi",
					Version:   "0.10.2+wasi-snapshot-preview1",
					Locations: []string{"fixtures/cargo/package-with-build-string.lock"},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.CargoLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
