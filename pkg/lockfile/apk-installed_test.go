package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestApkInstalledExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "empty",
			inputConfig: ScanInputMockConfig{
				path:         "empty_installed",
				fakeScanRoot: "fixtures/apk/with-os-release",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "not an installed",
			inputConfig: ScanInputMockConfig{
				path:         "not_installed",
				fakeScanRoot: "fixtures/apk/with-os-release",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "malformed",
			inputConfig: ScanInputMockConfig{
				path:         "malformed_installed",
				fakeScanRoot: "fixtures/apk/with-os-release",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "busybox",
					Version:   "",
					Locations: []string{"malformed_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					},
					Metadata: lockfile.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			name: "single",
			inputConfig: ScanInputMockConfig{
				path:         "single_installed",
				fakeScanRoot: "fixtures/apk/with-os-release",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "apk-tools",
					Version:   "2.12.10-r1",
					Locations: []string{"single_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "0188f510baadbae393472103427b9c1875117136",
					},
					Metadata: lockfile.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			name: "shuffled",
			inputConfig: ScanInputMockConfig{
				path:         "shuffled_installed",
				fakeScanRoot: "fixtures/apk/with-os-release",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "apk-tools",
					Version:   "2.12.10-r1",
					Locations: []string{"shuffled_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "0188f510baadbae393472103427b9c1875117136",
					},
					Metadata: lockfile.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			name: "multiple",
			inputConfig: ScanInputMockConfig{
				path:         "multiple_installed",
				fakeScanRoot: "fixtures/apk/with-os-release",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "alpine-baselayout-data",
					Version:   "3.4.0-r0",
					Locations: []string{"multiple_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
					},
					Metadata: lockfile.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
				{
					Name:      "musl",
					Version:   "1.2.3-r4",
					Locations: []string{"multiple_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "f93af038c3de7146121c2ea8124ba5ce29b4b058",
					},
					Metadata: lockfile.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
				{
					Name:      "busybox",
					Version:   "1.35.0-r29",
					Locations: []string{"multiple_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					},
					Metadata: lockfile.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			name: "multiple but no os source info",
			inputConfig: ScanInputMockConfig{
				path:         "multiple_installed",
				fakeScanRoot: "fixtures/apk/without-os-release",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "alpine-baselayout-data",
					Version:   "3.4.0-r0",
					Locations: []string{"multiple_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
					},
				},
				{
					Name:      "musl",
					Version:   "1.2.3-r4",
					Locations: []string{"multiple_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "f93af038c3de7146121c2ea8124ba5ce29b4b058",
					},
				},
				{
					Name:      "busybox",
					Version:   "1.35.0-r29",
					Locations: []string{"multiple_installed"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.ApkInstalledExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
