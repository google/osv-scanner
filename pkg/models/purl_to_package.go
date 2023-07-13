package models

import (
	"github.com/package-url/packageurl-go"
)

var purlEcosystems = map[string]Ecosystem{
	"cargo":    EcosystemCratesIO,
	"deb":      EcosystemDebian,
	"hex":      EcosystemHex,
	"golang":   EcosystemGo,
	"maven":    EcosystemMaven,
	"nuget":    EcosystemNuGet,
	"npm":      EcosystemNPM,
	"composer": EcosystemPackagist,
	"generic":  EcosystemOSSFuzz,
	"pypi":     EcosystemPyPI,
	"gem":      EcosystemRubyGems,
}

// PURLToPackage converts a Package URL string to models.PackageInfo
func PURLToPackage(purl string) (PackageInfo, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return PackageInfo{}, err
	}
	ecosystem, ok := purlEcosystems[parsedPURL.Type]
	if !ok {
		ecosystem = Ecosystem(parsedPURL.Type)
	}

	// PackageInfo expects the full namespace in the name for ecosystems that specify it.
	name := parsedPURL.Name
	if parsedPURL.Namespace != "" {
		switch ecosystem { //nolint:exhaustive
		case EcosystemMaven:
			// Maven uses : to separate namespace and package
			name = parsedPURL.Namespace + ":" + parsedPURL.Name
		case EcosystemDebian, EcosystemAlpine:
			// Debian and Alpine repeats their namespace in PURL, so don't add it to the name
			name = parsedPURL.Name
		default:
			name = parsedPURL.Namespace + "/" + parsedPURL.Name
		}
	}

	return PackageInfo{
		Name:      name,
		Ecosystem: string(ecosystem),
		Version:   parsedPURL.Version,
	}, nil
}
