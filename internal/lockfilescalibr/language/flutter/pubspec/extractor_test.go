package pubspec_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/flutter/pubspec"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
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
			inputPath: "pubspec.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pubspec.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pubspec.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/pubspec.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.pubspec.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := pubspec.Extractor{}
			got := e.FileRequired(tt.inputPath, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:              "invalid yaml",
			inputPath:         "testdata/not-yaml.txt",
			WantErrContaining: "could not extract from",
		},
		{
			Name:          "empty",
			inputPath:     "testdata/empty.lock",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:          "no packages",
			inputPath:     "testdata/no-packages.lock",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-package.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Locations: []string{"testdata/one-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "one package dev",
			inputPath: "testdata/one-package-dev.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Locations: []string{"testdata/one-package-dev.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name:      "two packages",
			inputPath: "testdata/two-packages.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "shelf",
					Version:   "1.3.2",
					Locations: []string{"testdata/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "shelf_web_socket",
					Version:   "1.0.2",
					Locations: []string{"testdata/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "mixed packages",
			inputPath: "testdata/mixed-packages.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Locations: []string{"testdata/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Locations: []string{"testdata/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "shelf",
					Version:   "1.3.2",
					Locations: []string{"testdata/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "shelf_web_socket",
					Version:   "1.0.2",
					Locations: []string{"testdata/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "package with git source",
			inputPath: "testdata/source-git.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flutter_rust_bridge",
					Version:   "1.32.0",
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "e5adce55eea0b74d3680e66a2c5252edf17b07e1",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "screen_retriever",
					Version:   "0.1.2",
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "406b9b038b2c1d779f1e7bf609c8c248be247372",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "tray_manager",
					Version:   "0.1.8",
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3aa37c86e47ea748e7b5507cbe59f2c54ebdb23a",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "window_manager",
					Version:   "0.2.7",
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "88487257cbafc501599ab4f82ec343b46acec020",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "toggle_switch",
					Version:   "1.4.0",
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "package with sdk source",
			inputPath: "testdata/source-sdk.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flutter_web_plugins",
					Version:   "0.0.0",
					Locations: []string{"testdata/source-sdk.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "package with path source",
			inputPath: "testdata/source-path.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "maa_core",
					Version:   "0.0.1",
					Locations: []string{"testdata/source-path.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
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
			e := pubspec.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
