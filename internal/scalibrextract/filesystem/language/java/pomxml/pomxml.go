// Package pomxml extracts pom.xml files.
package pomxml

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = pomxml.Name
)

// Extractor extracts Maven packages from pom.xml files.
type Extractor struct {
	pomxml.Extractor
}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}
