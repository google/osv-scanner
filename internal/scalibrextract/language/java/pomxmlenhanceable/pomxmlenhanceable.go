// Package pomxmlenhanceable provides an extractor for pom.xml files that can both do offline and transitive scanning.
package pomxmlenhanceable

import (
	"context"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/pomxmlenhanceable"
)

// Extractor extracts Maven packages from pom.xml files.
type Extractor struct {
	actual filesystem.Extractor
}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{actual: pomxml.New()} }

// Name of the extractor
func (e *Extractor) Name() string { return Name }

// Version of the extractor
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e *Extractor) Requirements() *plugin.Capabilities {
	req := e.actual.Requirements()
	req.Network = plugin.NetworkAny

	return req
}

// FileRequired returns true if the specified file matches Maven POM lockfile patterns.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	return e.actual.FileRequired(api)
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return e.actual.Extract(ctx, input)
}

var _ filesystem.Extractor = &Extractor{}

type enhanceable interface {
	Enhance(config pomxmlnet.Config)
}

// Enhance uses the given config to improve the abilities of this extractor,
// at the cost of additional requirements such as networking and direct fs access
func (e *Extractor) Enhance(config pomxmlnet.Config) {
	e.actual = pomxmlnet.New(config)
}

var _ enhanceable = &Extractor{}

// EnhanceIfPossible calls Extractor.Enhance with the given config if the
// provided extractor is an Extractor
func EnhanceIfPossible(extractor filesystem.Extractor, config pomxmlnet.Config) {
	us, ok := extractor.(enhanceable)

	if ok {
		us.Enhance(config)
	}
}
