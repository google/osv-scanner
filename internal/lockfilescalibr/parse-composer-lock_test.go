package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestComposerLockExtractor_FileRequired(t *testing.T) {
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
				Path: "composer.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/composer.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/composer.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/composer.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.composer.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.ComposerLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestComposerLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/composer/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/composer/empty.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/composer/one-package.json",
			},
			WantInventory: []*extractor.Inventory{
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
			Name: "one package dev",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/composer/one-package-dev.json",
			},
			WantInventory: []*extractor.Inventory{
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
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/composer/two-packages.json",
			},
			WantInventory: []*extractor.Inventory{
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
			Name: "two packages alt",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/composer/two-packages-alt.json",
			},
			WantInventory: []*extractor.Inventory{
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
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.ComposerLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
