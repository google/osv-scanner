package imodels

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	cdxmetadata "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmetadata "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
)

func Test_Name(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pkg  *extractor.Package
		want string
	}{
		{
			name: "Regular_package",
			pkg: &extractor.Package{
				Name: "regular-pkg",
			},
			want: "regular-pkg",
		},
		{
			name: "GIT_ecosystem_with_repo",
			pkg: &extractor.Package{
				Name: "openssl@3.5",
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo: "github.com/openssl/openssl",
				},
				Metadata: &osvscannerjson.Metadata{
					Ecosystem: "GIT",
				},
			},
			want: "github.com/openssl/openssl",
		},
		{
			name: "GIT_ecosystem_without_repo",
			pkg: &extractor.Package{
				Name: "openssl@3.5",
				SourceCode: &extractor.SourceCodeIdentifier{
					Repo: "",
				},
				Metadata: &osvscannerjson.Metadata{
					Ecosystem: "GIT",
				},
			},
			want: "openssl@3.5",
		},
		{
			name: "CycloneDX_Maven_package_with_group",
			pkg: &extractor.Package{
				Name:     "tomcat-embed-core",
				Version:  "9.0.80",
				PURLType: purl.TypeMaven,
				Metadata: &cdxmetadata.Metadata{
					PURL: &purl.PackageURL{
						Type:      purl.TypeMaven,
						Namespace: "org.apache.tomcat.embed",
						Name:      "tomcat-embed-core",
						Version:   "9.0.80",
					},
				},
			},
			want: "org.apache.tomcat.embed:tomcat-embed-core",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ParsePackage(tt.pkg).Name; got != tt.want {
				t.Errorf("ParsePackage(*extractor.Package).Name = %v, want %v", got, tt.want)
			}
		})
	}
}

// osv.dev orders RPM versions with an epoch, so packages in ecosystems whose
// records encode the epoch (Red Hat / AlmaLinux / Rocky Linux) must carry it.
// Ecosystems that store epoch-less records (e.g. openEuler) must NOT get an
// epoch, or every epoch-bearing package would be reported as already-fixed.
func Test_Version(t *testing.T) {
	t.Parallel()

	// rpm builds an RPM package that reports the given ecosystem via its OS metadata.
	rpm := func(version string, epoch int, meta *rpmmetadata.Metadata) *extractor.Package {
		meta.Epoch = epoch
		return &extractor.Package{Version: version, PURLType: purl.TypeRPM, Metadata: meta}
	}

	tests := []struct {
		name string
		pkg  *extractor.Package
		want string
	}{
		{
			name: "almalinux_epoch_prepended",
			pkg:  rpm("3.2.2-7.el9_6", 1, &rpmmetadata.Metadata{OSID: "almalinux", OSVersionID: "9.6"}),
			want: "1:3.2.2-7.el9_6",
		},
		{
			name: "redhat_epoch_prepended",
			pkg:  rpm("3.2.2-7.el9_6", 1, &rpmmetadata.Metadata{OSID: "rhel"}),
			want: "1:3.2.2-7.el9_6",
		},
		{
			name: "rocky_epoch_prepended",
			pkg:  rpm("1.1.1k-4.el8", 1, &rpmmetadata.Metadata{OSID: "rocky"}),
			want: "1:1.1.1k-4.el8",
		},
		{
			// openEuler packages carry epochs but its OSV feed drops them; prepending
			// the epoch would cause false negatives, so it must be left epoch-less.
			name: "openeuler_epoch_not_prepended",
			pkg:  rpm("7.1.0.28-3.oe2203", 1, &rpmmetadata.Metadata{OSID: "openEuler", OSVersionID: "22.03-LTS"}),
			want: "7.1.0.28-3.oe2203",
		},
		{
			name: "epoch_zero_unchanged",
			pkg:  rpm("2.35.2-63.el9", 0, &rpmmetadata.Metadata{OSID: "almalinux", OSVersionID: "9.6"}),
			want: "2.35.2-63.el9",
		},
		{
			name: "dpkg_version_unchanged",
			pkg:  &extractor.Package{Version: "2:1.0-1", PURLType: purl.TypeDebian, Metadata: &dpkgmetadata.Metadata{OSID: "ubuntu", OSVersionID: "22.04"}},
			want: "2:1.0-1",
		},
		{
			name: "sbom_cyclonedx_versionless_purl",
			pkg: &extractor.Package{
				Name:     "lodash",
				Version:  "4.17.16",
				PURLType: purl.TypeNPM,
				Plugins:  []string{"sbom/cdx"},
				Metadata: &cdxmetadata.Metadata{
					PURL: &purl.PackageURL{
						Type: purl.TypeNPM,
						Name: "lodash",
					},
				},
			},
			want: "4.17.16",
		},
		{
			name: "sbom_spdx_versionless_purl",
			pkg: &extractor.Package{
				Name:     "lodash",
				Version:  "4.17.16",
				PURLType: purl.TypeNPM,
				Plugins:  []string{"sbom/spdx"},
				Metadata: &spdxmetadata.Metadata{
					PURL: &purl.PackageURL{
						Type: purl.TypeNPM,
						Name: "lodash",
					},
				},
			},
			want: "4.17.16",
		},
		{
			name: "sbom_without_version",
			pkg: &extractor.Package{
				Name:     "lodash",
				Version:  "",
				PURLType: purl.TypeNPM,
				Plugins:  []string{"sbom/cdx"},
			},
			want: "",
		},
		{
			name: "go_stdlib_patch_version",
			pkg: &extractor.Package{
				Name:     "go",
				Version:  "1.20",
				PURLType: purl.TypeGolang,
			},
			want: "1.20.99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ParsePackage(tt.pkg).Version; got != tt.want {
				t.Errorf("ParsePackage(%q).Version = %q, want %q", tt.pkg.Ecosystem().String(), got, tt.want)
			}
		})
	}
}

func Test_NamesAndDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		pkg             *extractor.Package
		wantNames       []string
		wantDisplayName string
	}{
		{
			name:            "non_os_package",
			pkg:             &extractor.Package{Name: "lodash", PURLType: purl.TypeNPM},
			wantNames:       []string{"lodash"},
			wantDisplayName: "lodash",
		},
		{
			name: "dpkg_package_with_different_source_name",
			pkg: &extractor.Package{
				Name:     "libc6",
				PURLType: purl.TypeDebian,
				Metadata: &dpkgmetadata.Metadata{PackageName: "libc6", SourceName: "glibc", OSID: "ubuntu", OSVersionID: "26.04"},
			},
			wantNames:       []string{"libc6", "glibc"},
			wantDisplayName: "libc6 (source: glibc)",
		},
		{
			name: "dpkg_package_with_same_source_name",
			pkg: &extractor.Package{
				Name:     "bash",
				PURLType: purl.TypeDebian,
				Metadata: &dpkgmetadata.Metadata{PackageName: "bash", SourceName: "bash", OSID: "ubuntu", OSVersionID: "26.04"},
			},
			wantNames:       []string{"bash"},
			wantDisplayName: "bash",
		},
		{
			name: "dpkg_package_without_source_name",
			pkg: &extractor.Package{
				Name:     "libc6",
				PURLType: purl.TypeDebian,
				Metadata: &dpkgmetadata.Metadata{PackageName: "libc6", OSID: "ubuntu", OSVersionID: "26.04"},
			},
			wantNames:       []string{"libc6"},
			wantDisplayName: "libc6",
		},
		{
			name: "dpkg_package_without_binary_name_in_metadata",
			pkg: &extractor.Package{
				Name:     "libc6",
				PURLType: purl.TypeDebian,
				Metadata: &dpkgmetadata.Metadata{SourceName: "glibc", OSID: "ubuntu", OSVersionID: "26.04"},
			},
			wantNames:       []string{"glibc"},
			wantDisplayName: "glibc",
		},
		{
			name: "apk_package_with_different_origin_name",
			pkg: &extractor.Package{
				Name:     "libcrypto3",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{PackageName: "libcrypto3", OriginName: "openssl", OSID: "alpine", OSVersionID: "3.19"},
			},
			wantNames:       []string{"libcrypto3", "openssl"},
			wantDisplayName: "libcrypto3 (source: openssl)",
		},
		{
			name: "apk_package_without_origin_name",
			pkg: &extractor.Package{
				Name:     "musl",
				PURLType: purl.TypeApk,
				Metadata: &apkmetadata.Metadata{PackageName: "musl", OSID: "alpine", OSVersionID: "3.19"},
			},
			wantNames:       []string{"musl"},
			wantDisplayName: "musl",
		},
		{
			name: "rpm_package",
			pkg: &extractor.Package{
				Name:     "openssl-libs",
				PURLType: purl.TypeRPM,
				Metadata: &rpmmetadata.Metadata{PackageName: "openssl-libs", SourceRPM: "openssl-3.0.7-27.el9.src.rpm", OSID: "rhel"},
			},
			wantNames:       []string{"openssl-libs"},
			wantDisplayName: "openssl-libs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if diff := cmp.Diff(tt.wantNames, Names(tt.pkg)); diff != "" {
				t.Errorf("Names() mismatch (-want +got):\n%s", diff)
			}
			if got := DisplayName(tt.pkg); got != tt.wantDisplayName {
				t.Errorf("DisplayName() = %q, want %q", got, tt.wantDisplayName)
			}
		})
	}
}
