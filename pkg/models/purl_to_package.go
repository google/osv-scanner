package models

import (
	"github.com/package-url/packageurl-go"
)

// used like so: purlEcosystems[PkgURL.Type][PkgURL.Namespace]
// * means it should match any namespace string
var purlEcosystems = map[string]map[string]Ecosystem{
	"apk":      {"alpine": EcosystemAlpine},
	"cargo":    {"*": EcosystemCratesIO},
	"deb":      {"debian": EcosystemDebian},
	"hex":      {"*": EcosystemHex},
	"golang":   {"*": EcosystemGo},
	"maven":    {"*": EcosystemMaven},
	"nuget":    {"*": EcosystemNuGet},
	"npm":      {"*": EcosystemNPM},
	"composer": {"*": EcosystemPackagist},
	"generic":  {"*": EcosystemOSSFuzz},
	"pypi":     {"*": EcosystemPyPI},
	"gem":      {"*": EcosystemRubyGems},
}

func getPURLEcosystem(pkgURL packageurl.PackageURL) Ecosystem {
	ecoMap, ok := purlEcosystems[pkgURL.Type]
	if !ok {
		return Ecosystem(pkgURL.Type + ":" + pkgURL.Namespace)
	}

	wildcardRes, hasWildcard := ecoMap["*"]
	if hasWildcard {
		return wildcardRes
	}

	ecosystem, ok := ecoMap[pkgURL.Namespace]
	if !ok {
		return Ecosystem(pkgURL.Type + ":" + pkgURL.Namespace)
	}

	return ecosystem
}

// PURLToPackage converts a Package URL string to models.PackageInfo
func PURLToPackage(purl string) (PackageInfo, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return PackageInfo{}, err
	}
	ecosystem := getPURLEcosystem(parsedPURL)

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
