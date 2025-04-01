package output

import (
	"encoding/json"
	"io"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func isProbablyPackage(scannerPkg models.PackageVulns, docPkg *v2_3.Package) bool {
	purl := scannerPkg.Package.Extractor.ToPURL(&extractor.Inventory{
		Name:      scannerPkg.Package.Name,
		Version:   scannerPkg.Package.Version,
		Extractor: scannerPkg.Package.Extractor,
	})

	if purl == nil {
		return false
	}

	for _, ref := range docPkg.PackageExternalReferences {
		if ref.RefType == "purl" && ref.Category == "PACKAGE-MANAGER" {
			if ref.Locator == purl.String() {
				return true
			}
		}
	}

	return false
}

// PrintSPDXResults writes results to the provided writer in SPDX format
func PrintSPDXResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	scanResult := &scalibr.ScanResult{}

	for _, source := range vulnResult.Results {
		for _, pkg := range source.Packages {
			scanResult.Inventories = append(scanResult.Inventories, &extractor.Inventory{
				Name:      pkg.Package.Name,
				Version:   pkg.Package.Version,
				Extractor: pkg.Package.Extractor,
			})
			for _, vuln := range pkg.Vulnerabilities {
				scanResult.Findings = append(scanResult.Findings, &detector.Finding{
					Adv: &detector.Advisory{
						ID: &detector.AdvisoryID{
							Reference: vuln.ID,
						},
						Title:       vuln.Summary,
						Description: vuln.Details,
					},
				})
			}
		}
	}

	doc := converter.ToSPDX23(scanResult, converter.SPDXConfig{})

	for _, source := range vulnResult.Results {
		for _, scannerPkg := range source.Packages {
			for _, docPkg := range doc.Packages {
				if !isProbablyPackage(scannerPkg, docPkg) {
					continue
				}

				alreadyPresentAdvisories := make(map[string]struct{})
				for _, ref := range docPkg.PackageExternalReferences {
					if ref.RefType == "advisory" && ref.Category == "SECURITY" {
						alreadyPresentAdvisories[ref.Locator] = struct{}{}
					}
				}

				for _, vuln := range scannerPkg.Vulnerabilities {
					if _, ok := alreadyPresentAdvisories[vuln.ID]; ok {
						continue
					}

					docPkg.PackageExternalReferences = append(docPkg.PackageExternalReferences, &v2_3.PackageExternalReference{
						RefType:  "advisory",
						Category: "SECURITY",
						Locator:  vuln.ID,
					})
				}
			}
		}
	}

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	return encoder.Encode(doc)
}
