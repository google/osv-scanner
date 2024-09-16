package composerlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/php/composerlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
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
			inputPath: "composer.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/composer.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/composer.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/composer.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.composer.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := composerlock.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"testdata/one-package.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"testdata/one-package-dev.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"testdata/two-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					Locations: []string{"testdata/two-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages alt",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages-alt.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					Locations: []string{"testdata/two-packages-alt.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					Locations: []string{"testdata/two-packages-alt.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: othermetadata.DepGroupMetadata{
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
			e := composerlock.Extractor{}
			_, _ = extracttest.ExtractionTester(t, e, tt)
		})
	}
}
