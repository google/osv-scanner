package requirementsenhancable

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsnet"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "basic",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/requirements.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "alice",
					Version:   "1.0.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "bob",
					Version:   "2.0.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "chuck",
					Version:   "2.0.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "dave",
					Version:   "2.0.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "eve",
					Version:   "1.5.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "frank",
					Version:   "2.0.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/requirements.txt"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/basic-universe.yaml")
			extr := New()
			EnhanceIfPossible(extr, requirementsnet.Config{
				Extractor: &requirements.Extractor{},
				Client:    resolutionClient,
			})

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInventory := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInventory, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
