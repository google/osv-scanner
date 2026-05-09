package scanners_test

import (
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	rpmextractor "github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
)

func TestParseAsToPlugin_RPM(t *testing.T) {
	t.Parallel()

	plugins := scalibrplugin.Resolve([]string{"lockfile"}, []string{}, &cpb.PluginConfig{})

	tests := []string{"rpmdb", "Packages", "Packages.db", "rpmdb.sqlite"}
	for _, parseAs := range tests {
		t.Run(parseAs, func(t *testing.T) {
			t.Parallel()

			got, err := scanners.ParseAsToPlugin(parseAs, plugins)
			if err != nil {
				t.Fatalf("ParseAsToPlugin(%q) returned error: %v", parseAs, err)
			}

			if got.Name() != rpmextractor.Name {
				t.Fatalf("ParseAsToPlugin(%q) got %q, want %q", parseAs, got.Name(), rpmextractor.Name)
			}
		})
	}
}
