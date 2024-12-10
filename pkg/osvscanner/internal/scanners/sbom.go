package scanners

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
)

var SBOMExtractors = []filesystem.Extractor{
	spdx.Extractor{},
	cdx.Extractor{},
}
