package apkinstalled_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/alpine/apkinstalled"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "empty",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "empty_installed",
				FakeScanRoot: "testdata/with-os-release",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "not an installed",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "not_installed",
				FakeScanRoot: "testdata/with-os-release",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "malformed",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "malformed_installed",
				FakeScanRoot: "testdata/with-os-release",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "busybox",
					Version:   "",
					Locations: []string{"malformed_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					},
					Metadata: othermetadata.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			Name: "single",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "single_installed",
				FakeScanRoot: "testdata/with-os-release",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "apk-tools",
					Version:   "2.12.10-r1",
					Locations: []string{"single_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0188f510baadbae393472103427b9c1875117136",
					},
					Metadata: othermetadata.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			Name: "shuffled",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "shuffled_installed",
				FakeScanRoot: "testdata/with-os-release",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "apk-tools",
					Version:   "2.12.10-r1",
					Locations: []string{"shuffled_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0188f510baadbae393472103427b9c1875117136",
					},
					Metadata: othermetadata.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			Name: "multiple",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "multiple_installed",
				FakeScanRoot: "testdata/with-os-release",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "alpine-baselayout-data",
					Version:   "3.4.0-r0",
					Locations: []string{"multiple_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
					},
					Metadata: othermetadata.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
				{
					Name:      "musl",
					Version:   "1.2.3-r4",
					Locations: []string{"multiple_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f93af038c3de7146121c2ea8124ba5ce29b4b058",
					},
					Metadata: othermetadata.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
				{
					Name:      "busybox",
					Version:   "1.35.0-r29",
					Locations: []string{"multiple_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					},
					Metadata: othermetadata.DistroVersionMetadata{
						DistroVersionStr: "v3.20",
					},
				},
			},
		},
		{
			Name: "multiple but no os source info",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path:         "multiple_installed",
				FakeScanRoot: "testdata/without-os-release",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "alpine-baselayout-data",
					Version:   "3.4.0-r0",
					Locations: []string{"multiple_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
					},
				},
				{
					Name:      "musl",
					Version:   "1.2.3-r4",
					Locations: []string{"multiple_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f93af038c3de7146121c2ea8124ba5ce29b4b058",
					},
				},
				{
					Name:      "busybox",
					Version:   "1.35.0-r29",
					Locations: []string{"multiple_installed"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := apkinstalled.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
