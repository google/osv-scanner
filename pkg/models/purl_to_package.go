package models

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

// PURLToPackage converts a Package URL string to models.PackageInfo
func PURLToPackage(purl string) (PackageInfo, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return PackageInfo{}, err
	}
	ecosystem := purlEcosystems[parsedPURL.Type]
	if ecosystem == "" {
		ecosystem = parsedPURL.Type
	}

	// PackageInfo expects the full namespace in the name for ecosystems that specify it.
	name := parsedPURL.Name
	if parsedPURL.Namespace != "" {
		if ecosystem == string(EcosystemMaven) { // Maven uses : to separate namespace and package
			name = parsedPURL.Namespace + ":" + parsedPURL.Name
		} else if ecosystem == string(EcosystemDebian) || ecosystem == string(EcosystemAlpine) {
			// Debian and Alpine repeats their namespace in PURL, so don't add it to the name
			name = parsedPURL.Name
		} else {
			name = parsedPURL.Namespace + "/" + parsedPURL.Name
		}
	}

	return PackageInfo{
		Name:      name,
		Ecosystem: ecosystem,
		Version:   parsedPURL.Version,
	}, nil
}
