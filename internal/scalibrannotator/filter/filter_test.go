package filter

import (
	"context"
	"slices"
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
	pkgSBOMVersionlessPURL := &extractor.Package{
		Name:     "lodash",
		Version:  "4.17.16",
		PURLType: purl.TypeNPM,
		Plugins:  []string{"sbom/cdx"},
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
					PackageOverrides: []*config.PackageOverrideEntry{
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
		{
			name:            "sbom_with_version_and_versionless_purl_is_scannable",
			isContainerScan: false,
			showAllPackages: false,
			inputPackages:   []*extractor.Package{pkgSBOMVersionlessPURL},
			wantPackages:    []*extractor.Package{pkgSBOMVersionlessPURL},
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

func TestRemoveIgnoredPackagesAfterEnrichment(t *testing.T) {
	t.Parallel()

	newUbuntuPkg := func(binaryName, sourceName string) *extractor.Package {
		return &extractor.Package{
			Name:     binaryName,
			Version:  "1.0.0",
			PURLType: purl.TypeDebian,
			Metadata: &dpkgmeta.Metadata{
				PackageName: binaryName,
				SourceName:  sourceName,
				OSID:        "ubuntu",
				OSVersionID: "26.04",
			},
		}
	}

	libc6 := newUbuntuPkg("libc6", "glibc")
	libssl := newUbuntuPkg("libssl3t64", "openssl")
	zlib := newUbuntuPkg("zlib1g", "zlib")

	inv := &inventory.Inventory{
		Packages: []*extractor.Package{libc6, libssl, zlib},
		PackageVulns: []*inventory.PackageVuln{
			{Package: libc6},
			{Package: libssl},
			{Package: zlib},
		},
	}

	ignoreBySource := &config.PackageOverrideEntry{Name: "glibc", Ignore: true}
	ignoreVulnsOnly := &config.PackageOverrideEntry{Name: "openssl", Vulnerability: config.Vulnerability{Ignore: true}}
	configManager := &config.Manager{
		OverrideConfig: &config.Config{
			PackageOverrides: []*config.PackageOverrideEntry{ignoreBySource, ignoreVulnsOnly},
		},
	}

	RemoveIgnoredPackagesAfterEnrichment(inv, configManager)

	if diff := cmp.Diff([]*extractor.Package{libssl, zlib}, inv.Packages); diff != "" {
		t.Errorf("packages mismatch (-want +got):\n%s", diff)
	}

	wantVulns := []*inventory.PackageVuln{{Package: libssl}, {Package: zlib}}
	if diff := cmp.Diff(wantVulns, inv.PackageVulns); diff != "" {
		t.Errorf("package vulns mismatch (-want +got):\n%s", diff)
	}

	if !ignoreBySource.Used {
		t.Errorf("expected the ignore override to be marked as used")
	}
	if ignoreVulnsOnly.Used {
		t.Errorf("expected the vulnerability override not to be marked as used")
	}
}

func TestRemoveIgnoredPackagesAfterEnrichment_Cases(t *testing.T) {
	t.Parallel()

	newUbuntuPkg := func(binaryName, sourceName string) *extractor.Package {
		return &extractor.Package{
			Name:     binaryName,
			Version:  "1.0.0",
			PURLType: purl.TypeDebian,
			Metadata: &dpkgmeta.Metadata{
				PackageName: binaryName,
				SourceName:  sourceName,
				OSID:        "ubuntu",
				OSVersionID: "26.04",
			},
		}
	}

	// the binary-to-source enricher clones packages whose binary package maps to
	// multiple source packages, so they share a binary name but not a source name
	cloneA := newUbuntuPkg("libfoo1", "foo-a")
	cloneB := newUbuntuPkg("libfoo1", "foo-b")
	other := newUbuntuPkg("libbar1", "bar")

	tests := []struct {
		name          string
		configManager *config.Manager
		packages      []*extractor.Package
		wantPackages  []*extractor.Package
	}{
		{
			name:          "nil_config_manager",
			configManager: nil,
			packages:      []*extractor.Package{cloneA, other},
			wantPackages:  []*extractor.Package{cloneA, other},
		},
		{
			name: "no_matching_overrides",
			configManager: &config.Manager{
				OverrideConfig: &config.Config{
					PackageOverrides: []*config.PackageOverrideEntry{{Name: "nothing", Ignore: true}},
				},
			},
			packages:     []*extractor.Package{cloneA, other},
			wantPackages: []*extractor.Package{cloneA, other},
		},
		{
			name: "binary_name_removes_all_clones",
			configManager: &config.Manager{
				OverrideConfig: &config.Config{
					PackageOverrides: []*config.PackageOverrideEntry{{Name: "libfoo1", Ignore: true}},
				},
			},
			packages:     []*extractor.Package{cloneA, cloneB, other},
			wantPackages: []*extractor.Package{other},
		},
		{
			name: "source_name_removes_only_matching_clone",
			configManager: &config.Manager{
				OverrideConfig: &config.Config{
					PackageOverrides: []*config.PackageOverrideEntry{{Name: "foo-b", Ignore: true}},
				},
			},
			packages:     []*extractor.Package{cloneA, cloneB, other},
			wantPackages: []*extractor.Package{cloneA, other},
		},
		{
			name: "source_name_regex",
			configManager: &config.Manager{
				OverrideConfig: &config.Config{
					PackageOverrides: []*config.PackageOverrideEntry{{Name: "foo-.*", NameIsRegex: true, Ignore: true}},
				},
			},
			packages:     []*extractor.Package{cloneA, cloneB, other},
			wantPackages: []*extractor.Package{other},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			vulns := make([]*inventory.PackageVuln, 0, len(tt.packages))
			for _, pkg := range tt.packages {
				vulns = append(vulns, &inventory.PackageVuln{Package: pkg})
			}
			inv := &inventory.Inventory{
				Packages:     slices.Clone(tt.packages),
				PackageVulns: vulns,
			}

			RemoveIgnoredPackagesAfterEnrichment(inv, tt.configManager)

			if diff := cmp.Diff(tt.wantPackages, inv.Packages); diff != "" {
				t.Errorf("packages mismatch (-want +got):\n%s", diff)
			}

			gotVulnPackages := make([]*extractor.Package, 0, len(inv.PackageVulns))
			for _, pv := range inv.PackageVulns {
				gotVulnPackages = append(gotVulnPackages, pv.Package)
			}
			if diff := cmp.Diff(tt.wantPackages, gotVulnPackages); diff != "" {
				t.Errorf("package vulns mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
