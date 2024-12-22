package scanners

import (
	"context"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/scalibrextract"
	"github.com/google/osv-scanner/pkg/reporter"
)

var SBOMExtractors = []filesystem.Extractor{
	spdx.Extractor{},
	cdx.Extractor{},
}

func ScanSBOM(r reporter.Reporter, path string) ([]*extractor.Inventory, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		r.Errorf("Failed to resolved path %q with error: %s\n", path, err)
		return nil, err
	}

	invs, err := scalibrextract.ExtractWithExtractors(context.Background(), path, SBOMExtractors)
	if err != nil {
		r.Infof("Failed to parse SBOM %q with error: %s\n", path, err)
		return nil, err
	}

	pkgCount := len(invs)
	if pkgCount > 0 {
		r.Infof(
			"Scanned %s file and found %d %s\n",
			path,
			pkgCount,
			output.Form(pkgCount, "package", "packages"),
		)
	}

	return invs, nil
}
