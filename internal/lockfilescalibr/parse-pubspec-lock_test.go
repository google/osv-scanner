package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestPubspecLockExtractor_FileRequired(t *testing.T) {
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
				path: "pubspec.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pubspec.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pubspec.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pubspec.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.pubspec.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PubspecLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestPubspecLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid yaml",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/not-yaml.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "empty",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/empty.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/no-packages.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/one-package.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Locations: []string{"fixtures/pub/one-package.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "",
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
				path: "fixtures/pub/one-package-dev.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "build_runner",
					Version:   "2.2.1",
					Locations: []string{"fixtures/pub/one-package-dev.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "",
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
				path: "fixtures/pub/two-packages.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "shelf",
					Version:   "1.3.2",
					Locations: []string{"fixtures/pub/two-packages.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "mixed packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/mixed-packages.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "back_button_interceptor",
					Version:   "6.0.1",
					Locations: []string{"fixtures/pub/mixed-packages.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package with git source",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/source-git.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "flutter_rust_bridge",
					Version:   "1.32.0",
					Locations: []string{"fixtures/pub/source-git.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package with sdk source",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/source-sdk.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "flutter_web_plugins",
					Version:   "0.0.0",
					Locations: []string{"fixtures/pub/source-sdk.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package with path source",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pub/source-path.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "maa_core",
					Version:   "0.0.1",
					Locations: []string{"fixtures/pub/source-path.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PubspecLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

// func TestParsePubspecLock_InvalidYaml(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/not-yaml.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{})
// }

// func TestParsePubspecLock_Empty(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/empty.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{})
// }

// func TestParsePubspecLock_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/no-packages.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{})
// }

// func TestParsePubspecLock_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/one-package.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "back_button_interceptor",
// 			Version:   "6.0.1",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 		},
// 	})
// }

// func TestParsePubspecLock_OnePackageDev(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/one-package-dev.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "build_runner",
// 			Version:   "2.2.1",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			DepGroups: []string{"dev"},
// 		},
// 	})
// }

// func TestParsePubspecLock_TwoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/two-packages.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "shelf",
// 			Version:   "1.3.2",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 		},
// 		{
// 			Name:      "shelf_web_socket",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 		},
// 	})
// }

// func TestParsePubspecLock_MixedPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/mixed-packages.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "back_button_interceptor",
// 			Version:   "6.0.1",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 		},
// 		{
// 			Name:      "build_runner",
// 			Version:   "2.2.1",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "shelf",
// 			Version:   "1.3.2",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 		},
// 		{
// 			Name:      "shelf_web_socket",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 		},
// 	})
// }

// func TestParsePubspecLock_PackageWithGitSource(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/source-git.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "flutter_rust_bridge",
// 			Version:   "1.32.0",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "e5adce55eea0b74d3680e66a2c5252edf17b07e1",
// 		},
// 		{
// 			Name:      "screen_retriever",
// 			Version:   "0.1.2",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "406b9b038b2c1d779f1e7bf609c8c248be247372",
// 		},
// 		{
// 			Name:      "tray_manager",
// 			Version:   "0.1.8",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "3aa37c86e47ea748e7b5507cbe59f2c54ebdb23a",
// 		},
// 		{
// 			Name:      "window_manager",
// 			Version:   "0.2.7",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "88487257cbafc501599ab4f82ec343b46acec020",
// 		},
// 		{
// 			Name:      "toggle_switch",
// 			Version:   "1.4.0",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "",
// 		},
// 	})
// }

// func TestParsePubspecLock_PackageWithSdkSource(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/source-sdk.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "flutter_web_plugins",
// 			Version:   "0.0.0",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "",
// 		},
// 	})
// }

// func TestParsePubspecLock_PackageWithPathSource(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePubspecLock("fixtures/pub/source-path.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "maa_core",
// 			Version:   "0.0.1",
// 			Ecosystem: lockfilescalibr.PubEcosystem,
// 			Commit:    "",
// 		},
// 	})
// }
