package source_test

import (
	"bytes"
	"log/slog"
	"runtime"
	"slices"
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/internal/testlogger"
)

func TestLockfilePresetScansRPMDBFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("RPM extractor is not supported on Windows")
	}

	var stdout, stderr bytes.Buffer
	handler := slog.Default().Handler().(*testlogger.Handler)
	handler.AddInstance(cmdlogger.New(&stdout, &stderr))
	defer handler.Delete()

	plugins := scalibrplugin.Resolve([]string{"lockfile"}, nil, &cpb.PluginConfig{})
	extractors := make([]filesystem.Extractor, 0, len(plugins))
	for _, plug := range plugins {
		extractor, ok := plug.(filesystem.Extractor)
		if ok {
			extractors = append(extractors, extractor)
		}
	}

	inventory, statuses, err := filesystem.Run(t.Context(), &filesystem.Config{
		Extractors: extractors,
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS: scalibrfs.DirFS("./testdata/locks-rpm"),
		}},
		PathsToExtract: []string{"var/lib/rpm/Packages"},
		Stats:          stats.NoopCollector{},
	})
	if err != nil {
		t.Fatalf("filesystem.Run(): %v", err)
	}
	for _, status := range statuses {
		if status.Status != nil && status.Status.Status == plugin.ScanStatusFailed {
			t.Fatalf("extractor %s failed: %s", status.Name, status.Status.FailureReason)
		}
	}

	if got, want := len(inventory.Packages), 1; got != want {
		t.Fatalf("len(inventory.Packages) = %d, want %d", got, want)
	}

	pkg := inventory.Packages[0]
	if pkg.Name != "hello" {
		t.Errorf("pkg.Name = %q, want %q", pkg.Name, "hello")
	}
	if pkg.Version != "0.0.1-rls" {
		t.Errorf("pkg.Version = %q, want %q", pkg.Version, "0.0.1-rls")
	}
	if pkg.PURLType != purl.TypeRPM {
		t.Errorf("pkg.PURLType = %q, want %q", pkg.PURLType, purl.TypeRPM)
	}
	if !slices.Contains(pkg.Plugins, rpm.Name) {
		t.Errorf("pkg.Plugins = %v, want %q", pkg.Plugins, rpm.Name)
	}

	metadata, ok := pkg.Metadata.(*rpmmetadata.Metadata)
	if !ok {
		t.Fatalf("pkg.Metadata = %T, want *rpmmetadata.Metadata", pkg.Metadata)
	}
	if metadata.PackageName != "hello" {
		t.Errorf("metadata.PackageName = %q, want %q", metadata.PackageName, "hello")
	}
	if metadata.SourceRPM != "hello-0.0.1-rls.src.rpm" {
		t.Errorf("metadata.SourceRPM = %q, want %q", metadata.SourceRPM, "hello-0.0.1-rls.src.rpm")
	}
	if metadata.Epoch != 1 {
		t.Errorf("metadata.Epoch = %d, want %d", metadata.Epoch, 1)
	}
	if metadata.OSID != "fedora" {
		t.Errorf("metadata.OSID = %q, want %q", metadata.OSID, "fedora")
	}
	if metadata.OSVersionID != "32" {
		t.Errorf("metadata.OSVersionID = %q, want %q", metadata.OSVersionID, "32")
	}
	if metadata.Architecture != "x86_64" {
		t.Errorf("metadata.Architecture = %q, want %q", metadata.Architecture, "x86_64")
	}
}
