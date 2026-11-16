package config

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/purl"
)

// newDpkgPackage returns an Ubuntu package with the given binary and source
// package names; an empty source name mimics packages extracted from chisel
// manifests before their source name has been enriched.
func newDpkgPackage(binaryName, sourceName string) *extractor.Package {
	return &extractor.Package{
		Name:     binaryName,
		Version:  "2.43-2ubuntu2",
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmetadata.Metadata{
			PackageName:    binaryName,
			PackageVersion: "2.43-2ubuntu2",
			SourceName:     sourceName,
			OSID:           "ubuntu",
			OSVersionID:    "26.04",
		},
	}
}

func TestPackageOverrideEntry_matches_OSPackageNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry PackageOverrideEntry
		pkg   *extractor.Package
		want  bool
	}{
		{
			name:  "dpkg_binary_name_matches",
			entry: PackageOverrideEntry{Name: "libc6"},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  true,
		},
		{
			name:  "dpkg_source_name_matches",
			entry: PackageOverrideEntry{Name: "glibc"},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  true,
		},
		{
			name:  "dpkg_other_name_does_not_match",
			entry: PackageOverrideEntry{Name: "libc6-dev"},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  false,
		},
		{
			name:  "dpkg_binary_name_regex_matches",
			entry: PackageOverrideEntry{Name: "libc[0-9]+", NameIsRegex: true},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  true,
		},
		{
			name:  "dpkg_source_name_regex_matches",
			entry: PackageOverrideEntry{Name: "g.*c", NameIsRegex: true},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  true,
		},
		{
			name:  "dpkg_regex_must_match_a_whole_name",
			entry: PackageOverrideEntry{Name: "lib", NameIsRegex: true},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  false,
		},
		{
			name:  "dpkg_without_source_name_matches_binary_name",
			entry: PackageOverrideEntry{Name: "libc6"},
			pkg:   newDpkgPackage("libc6", ""),
			want:  true,
		},
		{
			name:  "dpkg_without_source_name_does_not_match_source_name",
			entry: PackageOverrideEntry{Name: "glibc"},
			pkg:   newDpkgPackage("libc6", ""),
			want:  false,
		},
		{
			name:  "dpkg_name_and_ecosystem_must_both_match",
			entry: PackageOverrideEntry{Name: "libc6", Ecosystem: "Debian"},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  false,
		},
		{
			name:  "dpkg_name_and_version_match",
			entry: PackageOverrideEntry{Name: "libc6", Ecosystem: "Ubuntu:26.04", Version: "2.43-2ubuntu2"},
			pkg:   newDpkgPackage("libc6", "glibc"),
			want:  true,
		},
		{
			name:  "apk_binary_name_matches",
			entry: PackageOverrideEntry{Name: "libcrypto3"},
			pkg: &extractor.Package{
				Name:     "libcrypto3",
				Version:  "3.1.4-r5",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{
					PackageName: "libcrypto3",
					OriginName:  "openssl",
					OSID:        "alpine",
					OSVersionID: "3.19",
				},
			},
			want: true,
		},
		{
			name:  "apk_origin_name_matches",
			entry: PackageOverrideEntry{Name: "openssl"},
			pkg: &extractor.Package{
				Name:     "libcrypto3",
				Version:  "3.1.4-r5",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{
					PackageName: "libcrypto3",
					OriginName:  "openssl",
					OSID:        "alpine",
					OSVersionID: "3.19",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.entry.matches(tt.pkg); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_FindPackageVulnerabilitiesOverride_OSPackageNames(t *testing.T) {
	t.Parallel()

	config := Config{
		PackageOverrides: []*PackageOverrideEntry{
			{Name: "libssl3t64", Vulnerability: Vulnerability{Ignore: true}, Reason: "binary"},
			{Name: "zlib", Vulnerability: Vulnerability{Ignore: true}, Reason: "source"},
		},
	}

	tests := []struct {
		name       string
		pkg        *extractor.Package
		wantReason string
	}{
		{name: "matched_by_binary_name", pkg: newDpkgPackage("libssl3t64", "openssl"), wantReason: "binary"},
		{name: "matched_by_source_name", pkg: newDpkgPackage("zlib1g", "zlib"), wantReason: "source"},
		{name: "not_matched", pkg: newDpkgPackage("libc6", "glibc"), wantReason: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := config.FindPackageVulnerabilitiesOverride(tt.pkg)

			gotReason := ""
			if got != nil {
				gotReason = got.Reason
			}

			if gotReason != tt.wantReason {
				t.Errorf("FindPackageVulnerabilitiesOverride() matched %q, want %q", gotReason, tt.wantReason)
			}
		})
	}
}
