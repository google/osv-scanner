package osvscanner_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scanner/v2/internal/tuxcare"
)

func TestEnrichHostContextWiredBeforeMatch(t *testing.T) {
	t.Parallel()
	marker := &extractor.Package{Metadata: &tuxcare.ChannelMarkerMetadata{Channel: "8.4"}}
	kernel := &extractor.Package{Name: "openssl", Version: "1.1.1g-15.el8.tuxcare.els7",
		Metadata: &rpmmetadata.Metadata{PackageName: "openssl", OSID: "centos", OSVersionID: "8"}}
	out := tuxcare.EnrichHostContext([]*extractor.Package{marker, kernel})
	if len(out) != 1 {
		t.Fatalf("marker not stripped: %d packages", len(out))
	}
}
