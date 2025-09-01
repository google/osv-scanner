// Package pomxmlenhanceable provides an extractor for pom.xml files that can both do offline and transitive scanning.
package pomxmlenhanceable

import (
	"context"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/pomxmlenhanceable"
)

// Extractor extracts Maven packages from pom.xml files.
type Extractor struct {
	offline filesystem.Extractor
	online  filesystem.Extractor
}

// New returns a new instance of the extractor.
func New() filesystem.Extractor {
	base := pomxml.New()
	return &Extractor{offline: base, online: base}
}

// Name of the extractor
func (e *Extractor) Name() string { return Name }

// Version of the extractor
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e *Extractor) Requirements() *plugin.Capabilities {
	req := e.online.Requirements()
	req.Network = plugin.NetworkAny

	return req
}

// FileRequired returns true if the specified file matches Maven POM lockfile patterns.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	return e.online.FileRequired(api)
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := e.online.Extract(ctx, input)
	if err == nil {
		return inv, nil
	}

	if e.online.Name() == e.offline.Name() {
		// online is the same as offline so we don't need to run extraction again.
		return inv, err
	}

	cmdlogger.Warnf(
		"failed to resolve transitive dependencies for %q, falling back to offline extraction: %s", input.Path, err.Error())

	// Fallback to the base extractor if the enhanced extraction failed.
	f, err := input.FS.Open(input.Path)
	if err != nil {
		return inventory.Inventory{}, err
	}
	input.Reader = f
	defer f.Close()

	return e.offline.Extract(ctx, input)
}

var _ filesystem.Extractor = &Extractor{}

type enhanceable interface {
	Enhance(config pomxmlnet.Config)
}

// Enhance uses the given config to improve the abilities of this extractor,
// at the cost of additional requirements such as networking and direct fs access
func (e *Extractor) Enhance(config pomxmlnet.Config) {
	e.online = pomxmlnet.New(config)
}

var _ enhanceable = &Extractor{}

// EnhanceIfPossible calls Extractor.Enhance with the given config if the
// provided plug(in) is an Extractor
func EnhanceIfPossible(plug plugin.Plugin, config pomxmlnet.Config) {
	us, ok := plug.(enhanceable)

	if ok {
		us.Enhance(config)
	}
}
