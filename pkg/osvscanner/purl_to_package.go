package osvscanner

import (
	"github.com/google/osv-scanner/pkg/models"
	"github.com/package-url/packageurl-go"
)

var purlEcosystems = map[string]string{
	"cargo":    "crates.io",
	"deb":      "Debian",
	"hex":      "Hex",
	"golang":   "Go",
	"maven":    "Maven",
	"nuget":    "NuGet",
	"npm":      "npm",
	"composer": "Packagist",
	"generic":  "OSS-Fuzz",
	"pypi":     "PyPI",
	"gem":      "RubyGems",
}

func PURLToPackage(purl string) (models.PackageInfo, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return models.PackageInfo{}, err
	}
	ecosystem := purlEcosystems[parsedPURL.Type]
	if ecosystem == "" {
		ecosystem = parsedPURL.Type
	}
	return models.PackageInfo{
		Name:      parsedPURL.Name,
		Ecosystem: ecosystem,
		Version:   parsedPURL.Version,
	}, nil
}
