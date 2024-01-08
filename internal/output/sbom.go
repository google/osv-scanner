package output

import (
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/package-url/packageurl-go"
)

var purlEcosystems = map[string]string{
	"crates.io": "cargo",
	"Debian":    "deb",
	"Hex":       "hex",
	"Go":        "golang",
	"Maven":     "maven",
	"NuGet":     "buget",
	"npm":       "npm",
	"Packagist": "composer",
	"OSS-Fuzz":  "generic",
	"PyPI":      "pypi",
	"RubyGems":  "gem",
}

// PrintCycloneDxSbomResults prints parsed results into a CycloneDX SBOM format.
func PrintCycloneDxSbomResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	components := []cyclonedx.Component{}

	// Working directory used to simplify path
	workingDir, workingDirErr := os.Getwd()
	for _, sourceRes := range vulnResult.Results {
		for _, pkg := range sourceRes.Packages {
			source := sourceRes.Source
			if workingDirErr == nil {
				sourcePath, err := filepath.Rel(workingDir, source.Path)
				if err == nil { // Simplify the path if possible
					source.Path = sourcePath
				}
			}

			// TODO @rtvlad: follow up on this
			// When request to OSV, Occur with GIT Ecosystem
			if pkg.Package.Ecosystem == "GIT" {
				continue
			}

			purl := PackageToPurl(pkg)
			component := cyclonedx.Component{
				BOMRef:  purl,
				Type:    cyclonedx.ComponentTypeLibrary,
				Name:    pkg.Package.Name,
				Version: pkg.Package.Version,
				// https://github.com/package-url/purl-spec
				PackageURL: purl,
			}
			components = append(components, component)
		}
	}

	bom := cyclonedx.NewBOM()
	bom.Components = &components

	encoder := cyclonedx.NewBOMEncoder(outputWriter, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	return encoder.EncodeVersion(bom, cyclonedx.SpecVersion1_4)
}

func PackageToPurl(pkg models.PackageVulns) string {
	ecosystem := purlEcosystems[pkg.Package.Ecosystem]
	if ecosystem == "" {
		ecosystem = pkg.Package.Ecosystem
	}

	instance := packageurl.NewPackageURL(ecosystem, "", pkg.Package.Name, pkg.Package.Version, nil, "")

	// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
	if ecosystem == "maven" {
		instance.Name = strings.ReplaceAll(instance.Name, ":", "/")
	}

	purl, err := url.QueryUnescape(instance.ToString())
	if err != nil {
		panic(err)
	}

	return purl
}
