package output

import (
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

func PURLToPackage(purl string) (Package, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return Package{}, err
	}
	ecosystem := purlEcosystems[parsedPURL.Type]
	if ecosystem == "" {
		ecosystem = parsedPURL.Type
	}
	return Package{
		Name:      parsedPURL.Name,
		Ecosystem: ecosystem,
		Version:   parsedPURL.Version,
	}, nil
}
