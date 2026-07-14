package imodels

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Name(tt.pkg); got != tt.want {
				t.Errorf("Name(*extractor.Package) = %v, want %v", got, tt.want)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Version(tt.pkg); got != tt.want {
				t.Errorf("Version(%q) = %q, want %q", tt.pkg.Ecosystem().String(), got, tt.want)
			}
		})
	}
}
