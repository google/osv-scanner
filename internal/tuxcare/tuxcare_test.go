package tuxcare

import (
	"testing"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
)

func rpmPkg(name, version, osID, osVersionID string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		Metadata: &rpmmetadata.Metadata{PackageName: name, OSID: osID, OSVersionID: osVersionID},
	}
}

func TestRepoFileChannel(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"centos8.4-els.repo": "8.4",
		"centos8.5-els.repo": "8.5",
		"other.repo":         "",
	}
	for fname, want := range cases {
		if got := RepoFileNames[fname]; got != want {
			t.Errorf("RepoFileNames[%q] = %q, want %q", fname, got, want)
		}
	}
}

func TestEnrichHostContext_StampsCentOS8AndStripsMarker(t *testing.T) {
	t.Parallel()
	marker := &extractor.Package{Metadata: &ChannelMarkerMetadata{Channel: "8.5"}}
	kernel := rpmPkg("openssl", "1.1.1g-15.el8.tuxcare.els7", "centos", "8")
	pkgs := []*extractor.Package{marker, kernel}

	out := EnrichHostContext(pkgs)

	// marker stripped
	if len(out) != 1 || out[0] != kernel {
		t.Fatalf("expected only the kernel package to remain, got %d packages", len(out))
	}
	// CentOS-8 package stamped with the channel minor
	m := kernel.Metadata.(*rpmmetadata.Metadata)
	if m.OSVersionID != "8.5" {
		t.Errorf("OSVersionID = %q, want %q (stamped)", m.OSVersionID, "8.5")
	}
	// and now routes
	overlay := OverlayPackage(kernel)
	if overlay == nil || overlay.GetEcosystem() != "TuxCare:CentOS:8.5" {
		t.Errorf("OverlayPackage ecosystem = %v, want TuxCare:CentOS:8.5", overlay)
	}
}

func TestEnrichHostContext_NoMarkerLeavesCentOS8Unrouted(t *testing.T) {
	t.Parallel()
	kernel := rpmPkg("openssl", "1.1.1g-15.el8.tuxcare.els7", "centos", "8")
	out := EnrichHostContext([]*extractor.Package{kernel})
	if len(out) != 1 {
		t.Fatalf("expected package retained, got %d", len(out))
	}
	if OverlayPackage(kernel) != nil {
		t.Errorf("CentOS-8 with no channel marker must not route, got a route")
	}
}

// TestChannelMarkerMetadata_ProtoRegistration is a regression test for C1(b).
// ChannelMarkerMetadata must be registered with metadata.RegisterNil so that
// metadata.StructToProto returns (nil, nil) rather than ErrStructNotRegistered.
// Without the init() registration this test fails.
func TestChannelMarkerMetadata_ProtoRegistration(t *testing.T) {
	t.Parallel()
	marker := &ChannelMarkerMetadata{Channel: "8.4"}
	anyMsg, err := metadata.StructToProto(marker)
	if err != nil {
		t.Fatalf("metadata.StructToProto(*ChannelMarkerMetadata) returned error: %v; want nil (RegisterNil registration missing?)", err)
	}
	if anyMsg != nil {
		t.Errorf("metadata.StructToProto(*ChannelMarkerMetadata) = %v, want nil (RegisterNil should produce nil)", anyMsg)
	}
}

// TestEnrichHostContext_ConflictingChannels verifies that when multiple marker packages
// report different channels, no stamping is done (safe no-route).
func TestEnrichHostContext_ConflictingChannels(t *testing.T) {
	t.Parallel()
	marker84 := &extractor.Package{Metadata: &ChannelMarkerMetadata{Channel: "8.4"}}
	marker85 := &extractor.Package{Metadata: &ChannelMarkerMetadata{Channel: "8.5"}}
	kernel := rpmPkg("openssl", "1.1.1g-15.el8.tuxcare.els7", "centos", "8")
	pkgs := []*extractor.Package{marker84, marker85, kernel}

	out := EnrichHostContext(pkgs)

	// Both markers stripped
	if len(out) != 1 || out[0] != kernel {
		t.Fatalf("expected only kernel package to remain, got %d packages", len(out))
	}
	// No stamping — OSVersionID stays "8" (major only), so does not route
	m := kernel.Metadata.(*rpmmetadata.Metadata)
	if m.OSVersionID != "8" {
		t.Errorf("OSVersionID = %q, want %q (must not be stamped on conflict)", m.OSVersionID, "8")
	}
	if OverlayPackage(kernel) != nil {
		t.Errorf("CentOS-8 with conflicting markers must not route, got a route")
	}
}
