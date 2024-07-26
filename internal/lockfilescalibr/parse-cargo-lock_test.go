package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestCargoLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "Empty path",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "Cargo.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Cargo.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Cargo.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Cargo.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.Cargo.lock",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.CargoLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestCargoLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "Invalid toml",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/not-toml.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/empty.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/one-package.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/one-package.lock"},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/two-packages.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
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
			name: "two packages with local",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/two-packages-with-local.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
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
			name: "package with build string",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/package-with-build-string.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.CargoLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
