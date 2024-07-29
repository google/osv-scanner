package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestPubspecLockExtractor_FileRequired(t *testing.T) {
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
				Path: "pubspec.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/pubspec.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/pubspec.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/pubspec.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.pubspec.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PubspecLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestPubspecLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid yaml",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/not-yaml.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "empty",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/no-packages.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Locations: []string{"fixtures/pub/one-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
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
				Path: "fixtures/pub/one-package-dev.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Locations: []string{"fixtures/pub/one-package-dev.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
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
				Path: "fixtures/pub/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "shelf",
					Version:   "1.3.2",
					Locations: []string{"fixtures/pub/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "shelf_web_socket",
					Version:   "1.0.2",
					Locations: []string{"fixtures/pub/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "mixed packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/mixed-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Locations: []string{"fixtures/pub/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Locations: []string{"fixtures/pub/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "shelf",
					Version:   "1.3.2",
					Locations: []string{"fixtures/pub/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "shelf_web_socket",
					Version:   "1.0.2",
					Locations: []string{"fixtures/pub/mixed-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with git source",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/source-git.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flutter_rust_bridge",
					Version:   "1.32.0",
					Locations: []string{"fixtures/pub/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "e5adce55eea0b74d3680e66a2c5252edf17b07e1",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "screen_retriever",
					Version:   "0.1.2",
					Locations: []string{"fixtures/pub/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "406b9b038b2c1d779f1e7bf609c8c248be247372",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "tray_manager",
					Version:   "0.1.8",
					Locations: []string{"fixtures/pub/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3aa37c86e47ea748e7b5507cbe59f2c54ebdb23a",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "window_manager",
					Version:   "0.2.7",
					Locations: []string{"fixtures/pub/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "88487257cbafc501599ab4f82ec343b46acec020",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "toggle_switch",
					Version:   "1.4.0",
					Locations: []string{"fixtures/pub/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with sdk source",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/source-sdk.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "flutter_web_plugins",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pub/source-sdk.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with path source",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pub/source-path.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "maa_core",
					Version:   "0.0.1",
					Locations: []string{"fixtures/pub/source-path.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
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
			e := lockfilescalibr.PubspecLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
