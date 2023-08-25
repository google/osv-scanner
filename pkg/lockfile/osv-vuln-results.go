package lockfile

import (
	"encoding/json"
	"fmt"

	"github.com/google/osv-scanner/pkg/models"
)

const OSVScannerEcosystem Ecosystem = "OSV-Scanner-Results"

func ParseOSVScannerResults(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, OSVScannerResultsExtractor{})
}

type OSVScannerResultsExtractor struct{}

func (e OSVScannerResultsExtractor) ShouldExtract(path string) bool {
	// The output will always be a custom json file, so don't return a default should extract
	return false
}

func (e OSVScannerResultsExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	parsedResults := models.VulnerabilityResults{}
	err := json.NewDecoder(f).Decode(&parsedResults)

	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := []PackageDetails{}
	for _, res := range parsedResults.Results {
		for _, pkg := range res.Packages {
			packages = append(packages, PackageDetails{
				Name:      pkg.Package.Name,
				Ecosystem: Ecosystem(pkg.Package.Ecosystem),
				Version:   pkg.Package.Version,
				CompareAs: Ecosystem(pkg.Package.Ecosystem),
				Source:    res.Source.Path,
			})
		}
	}

	return packages, nil
}

var _ Extractor = OSVScannerResultsExtractor{}

// FromOSVScannerResults attempts to extract packages stored in the OSVScannerResults format
func FromOSVScannerResults(pathToInstalled string) (Lockfile, error) {
	packages, err := extractFromFile(pathToInstalled, OSVScannerResultsExtractor{})

	return Lockfile{
		FilePath: pathToInstalled,
		ParsedAs: "osv-scanner-results",
		Packages: packages,
	}, err
}
