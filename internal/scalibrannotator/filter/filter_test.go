package filter

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/config"
)

func TestAnnotator_Annotate(t *testing.T) {
	t.Parallel()

	pkgScannable := &extractor.Package{
		Name:     "foo",
		Version:  "1.0.0",
		PURLType: purl.TypeNPM,
	}
	pkgUnscannableNoVersion := &extractor.Package{
		Name:     "bar",
		PURLType: purl.TypeNPM,
	}
	pkgUnscannableShortHash := &extractor.Package{
		Name: "short-hash",
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: "1234abc",
		},
		PURLType: purl.TypeNPM,
	}
	pkgScannableFullHash := &extractor.Package{
		Name: "full-hash",
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: "1234567890abcdef1234567890abcdef12345678",
		},
		PURLType: purl.TypeNPM,
	}
	pkgLinuxKernel := &extractor.Package{
		Name:     "linux",
		Version:  "6.1.0",
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmeta.Metadata{
			OSID:        "debian",
			OSVersionID: "12",
		},
	}
	pkgIgnored := &extractor.Package{
		Name:     "ignored-pkg",
		Version:  "1.2.3",
		PURLType: purl.TypeNPM,
	}

	tests := []struct {
		name                 string
		isContainerScan      bool
		showAllPackages      bool
		configManager        *config.Manager
		inputPackages        []*extractor.Package
		wantPackages         []*extractor.Package
		wantFilteredPackages []*extractor.Package
	}{
		{
			name:            "basic_scannable_packages",
			isContainerScan: false,
			showAllPackages: false,
			inputPackages:   []*extractor.Package{pkgScannable, pkgScannableFullHash},
			wantPackages:    []*extractor.Package{pkgScannable, pkgScannableFullHash},
		},
		{
			name:                 "filter_unscannable_without_all_packages",
			isContainerScan:      false,
			showAllPackages:      false,
			inputPackages:        []*extractor.Package{pkgScannable, pkgUnscannableNoVersion, pkgUnscannableShortHash},
			wantPackages:         []*extractor.Package{pkgScannable},
			wantFilteredPackages: nil,
		},
		{
			name:                 "filter_unscannable_with_all_packages",
			isContainerScan:      false,
			showAllPackages:      true,
			inputPackages:        []*extractor.Package{pkgScannable, pkgUnscannableNoVersion, pkgUnscannableShortHash},
			wantPackages:         []*extractor.Package{pkgScannable},
			wantFilteredPackages: []*extractor.Package{pkgUnscannableNoVersion, pkgUnscannableShortHash},
		},
		{
			name:            "container_scan_filters_linux_kernel",
			isContainerScan: true,
			showAllPackages: false,
			inputPackages:   []*extractor.Package{pkgScannable, pkgLinuxKernel},
			wantPackages:    []*extractor.Package{pkgScannable},
		},
		{
			name:            "non_container_scan_keeps_linux_kernel",
			isContainerScan: false,
			showAllPackages: false,
			inputPackages:   []*extractor.Package{pkgScannable, pkgLinuxKernel},
			wantPackages:    []*extractor.Package{pkgScannable, pkgLinuxKernel},
		},
		{
			name:            "filter_ignored_packages",
			isContainerScan: false,
			showAllPackages: false,
			configManager: &config.Manager{
				OverrideConfig: &config.Config{
					PackageOverrides: []config.PackageOverrideEntry{
						{
							Name:      "ignored-pkg",
							Ecosystem: "npm",
							Ignore:    true,
						},
					},
				},
			},
			inputPackages: []*extractor.Package{pkgScannable, pkgIgnored},
			wantPackages:  []*extractor.Package{pkgScannable},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := NewAnnotator(tt.configManager, tt.isContainerScan, tt.showAllPackages)
			results := &inventory.Inventory{Packages: tt.inputPackages}

			err := a.Annotate(context.Background(), nil, results)
			if err != nil {
				t.Fatalf("Annotate() error = %v", err)
			}

			opt := cmpopts.SortSlices(func(a, b *extractor.Package) bool { return a.Name < b.Name })
			if diff := cmp.Diff(tt.wantPackages, results.Packages, opt); diff != "" {
				t.Errorf("Annotate() packages mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.wantFilteredPackages, a.FilteredPackages(), opt); diff != "" {
				t.Errorf("Annotate() filtered packages mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
