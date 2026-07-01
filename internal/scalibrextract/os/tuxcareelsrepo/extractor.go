// Package tuxcareelsrepo detects a TuxCare CentOS-8 ELS repo file and emits a marker
// carrying the channel, consumed by the host-context enricher in internal/tuxcare.
package tuxcareelsrepo

import (
	"context"
	"path/filepath"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/tuxcare"
)

// Name is the unique name of this extractor.
const Name = "os/tuxcare-els-repo"

// Extractor emits a marker package for a recognized TuxCare CentOS-8 ELS repo file.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

func (e *Extractor) fileRequiredPath(base string) bool {
	_, ok := tuxcare.RepoFileNames[base]
	return ok
}

// FileRequired matches the TuxCare CentOS-8 ELS repo files.
func (e *Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return e.fileRequiredPath(filepath.Base(fapi.Path()))
}

// Extract emits a single marker package carrying the detected channel.
func (e *Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	channel := tuxcare.RepoFileNames[filepath.Base(input.Path)]
	if channel == "" {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{Packages: []*extractor.Package{{
		Name:     "tuxcare-els-channel-marker",
		Metadata: &tuxcare.ChannelMarkerMetadata{Channel: channel},
		Location: extractor.LocationFromPath(input.Path),
	}}}, nil
}

// ToPURL converts a package created by this extractor into a PURL.
func (e *Extractor) ToPURL(_ *extractor.Package) *purl.PackageURL { return nil }
