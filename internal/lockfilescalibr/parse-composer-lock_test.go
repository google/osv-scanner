package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestComposerLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "composer.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/composer.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/composer.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/composer.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.composer.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.ComposerLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestComposerLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/composer/not-json.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/composer/empty.json",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/composer/one-package.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"fixtures/composer/one-package.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/composer/one-package-dev.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"fixtures/composer/one-package-dev.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/composer/two-packages.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"fixtures/composer/two-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					Locations: []string{"fixtures/composer/two-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			name: "two packages alt",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/composer/two-packages-alt.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"fixtures/composer/two-packages-alt.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					Locations: []string{"fixtures/composer/two-packages-alt.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.ComposerLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
