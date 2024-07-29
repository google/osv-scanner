package extractor

import (
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

// SourceCodeIdentifier lists additional identifiers for source code software packages (e.g. NPM).
type SourceCodeIdentifier struct {
	Repo   string
	Commit string
}

// Extractor is the common interface of inventory extraction plugins..
type Extractor interface {
	plugin.Plugin
	// ToPURL converts an inventory created by this extractor into a PURL.
	ToPURL(i *Inventory) (*packageurl.PackageURL, error)
	// ToCPEs converts an inventory created by this extractor into CPEs, if supported.
	ToCPEs(i *Inventory) ([]string, error)
	// Ecosystem returns the Ecosystem of the given inventory created by this extractor.
	// For software packages this corresponds to an OSV ecosystem value, e.g. PyPI.
	Ecosystem(i *Inventory) (string, error)
}

// TODO: Where to put this?
type Annotation int

type Inventory struct {
	// Source code-level identifier.
	SourceCode *SourceCodeIdentifier
	Name       string
	// The version of this package. The version follows the versioning scheme for specified Ecosystem.
	Version string
	// The paths of the files from which the information about the inventory is extracted
	Locations []string
	// The Extractor that found this software instance. Set by the core library.
	Extractor Extractor
	// The additional data found in the package, specific to the extractor.
	Metadata    any
	Annotations []Annotation // See go/scalibr-annotations for details.
}

func (i Inventory) Ecosystem() (string, error) {
	return i.Extractor.Ecosystem(&i)
}
