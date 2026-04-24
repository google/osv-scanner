package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	scalibrpurl "github.com/google/osv-scalibr/purl"
	purlutil "github.com/google/osv-scanner/v2/internal/utility/purl"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// PrintSPDXResults writes results to the provided writer in SPDX format
func PrintSPDXResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	scanResult := &scalibr.ScanResult{}

	for _, source := range vulnResult.Results {
		for _, pkg := range source.Packages {
			inv := pkg.Package.Inventory
			if inv == nil {
				var err error
				inv, err = inventoryFromPackageInfo(pkg.Package)
				if err != nil {
					return err
				}
			}
			if inv != nil {
				scanResult.Inventory.Packages = append(scanResult.Inventory.Packages, inv)
			}
		}
	}

	// TODO(#1783): Allow user configuration
	doc := spdx.ToSPDX23(scanResult.Inventory, spdx.Config{})

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	return encoder.Encode(doc)
}

// inventoryFromPackageInfo constructs a synthetic extractor.Package from a PackageInfo
// for packages that don't have a populated Inventory field (e.g., loaded from osv-scanner.json).
func inventoryFromPackageInfo(pkg models.PackageInfo) (*extractor.Package, error) {
	eco, err := osvecosystem.Parse(pkg.Ecosystem)
	if err != nil {
		return nil, err
	}

	purlType, ok := purlutil.EcosystemToPURLMapper[eco.Ecosystem]
	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem: %s", pkg.Ecosystem)
	}

	inv := &extractor.Package{
		Name:     pkg.Name,
		Version:  pkg.Version,
		PURLType: purlType,
	}

	// Maven names in osv-scanner are "groupId:artifactId".
	// The scalibr Maven PURL converter requires Metadata with GroupID/ArtifactID
	// to produce the correct PURL (pkg:maven/groupId/artifactId@version).
	if purlType == scalibrpurl.TypeMaven {
		parts := strings.SplitN(pkg.Name, ":", 2)
		if len(parts) == 2 {
			inv.Metadata = &javalockfile.Metadata{
				GroupID:    parts[0],
				ArtifactID: parts[1],
			}
		}
	}

	return inv, nil
}
