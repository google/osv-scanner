package scanners_test

import (
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/pkg/osvscanner/internal/scanners"
)

func TestParseAsToPlugin_RPMDB(t *testing.T) {
	t.Parallel()

	plugins := scalibrplugin.Resolve([]string{"lockfile"}, nil, &cpb.PluginConfig{})

	extractor, err := scanners.ParseAsToPlugin("rpmdb", plugins)
	if err != nil {
		t.Fatalf("ParseAsToPlugin(%q): %v", "rpmdb", err)
	}
	if extractor.Name() != rpm.Name {
		t.Fatalf("ParseAsToPlugin(%q).Name() = %q, want %q", "rpmdb", extractor.Name(), rpm.Name)
	}
}
