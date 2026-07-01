package osvmatcher

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
)

// osv.dev orders RPM versions with an epoch, so queries to ecosystems whose
// records encode the epoch (Red Hat / AlmaLinux / Rocky Linux) must carry it.
// Ecosystems that store epoch-less records (e.g. openEuler) must NOT get an
// epoch, or every epoch-bearing package would be reported as already-fixed.
func TestQueryVersion(t *testing.T) {
	t.Parallel()

	rpm := func(version string, epoch int) *extractor.Package {
		return &extractor.Package{Version: version, Metadata: &rpmmetadata.Metadata{Epoch: epoch}}
	}

	tests := []struct {
		name      string
		pkg       *extractor.Package
		ecosystem string
		want      string
	}{
		{
			name:      "almalinux_epoch_prepended",
			pkg:       rpm("3.2.2-7.el9_6", 1),
			ecosystem: "AlmaLinux:9.6",
			want:      "1:3.2.2-7.el9_6",
		},
		{
			name:      "redhat_epoch_prepended",
			pkg:       rpm("3.2.2-7.el9_6", 1),
			ecosystem: "Red Hat",
			want:      "1:3.2.2-7.el9_6",
		},
		{
			name:      "rocky_epoch_prepended",
			pkg:       rpm("1.1.1k-4.el8", 1),
			ecosystem: "Rocky Linux:8",
			want:      "1:1.1.1k-4.el8",
		},
		{
			// openEuler packages carry epochs but its OSV feed drops them; sending
			// the epoch would cause false negatives, so it must be left epoch-less.
			name:      "openeuler_epoch_not_prepended",
			pkg:       rpm("7.1.0.28-3.oe2203", 1),
			ecosystem: "openEuler:22.03-LTS",
			want:      "7.1.0.28-3.oe2203",
		},
		{
			name:      "epoch_zero_unchanged",
			pkg:       rpm("2.35.2-63.el9", 0),
			ecosystem: "AlmaLinux:9.6",
			want:      "2.35.2-63.el9",
		},
		{
			name:      "dpkg_version_unchanged",
			pkg:       &extractor.Package{Version: "2:1.0-1", Metadata: &dpkgmetadata.Metadata{}},
			ecosystem: "Ubuntu:22.04",
			want:      "2:1.0-1",
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := queryVersion(tt.pkg, tt.ecosystem); got != tt.want {
				t.Errorf("queryVersion(_, %q) = %q, want %q", tt.ecosystem, got, tt.want)
			}
		})
	}
}
