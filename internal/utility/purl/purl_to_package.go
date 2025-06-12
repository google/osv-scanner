package purl

import (
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/package-url/packageurl-go"
)

// used like so: purlEcosystems[PkgURL.Type][PkgURL.Namespace]
// * means it should match any namespace string
var purlEcosystems = map[string]map[string]osvschema.Ecosystem{
	"apk":   {"alpine": osvschema.EcosystemAlpine},
	"cargo": {"*": osvschema.EcosystemCratesIO},
	"deb": {"debian": osvschema.EcosystemDebian,
		"ubuntu": osvschema.EcosystemUbuntu},
	"hex":      {"*": osvschema.EcosystemHex},
	"golang":   {"*": osvschema.EcosystemGo},
	"maven":    {"*": osvschema.EcosystemMaven},
	"nuget":    {"*": osvschema.EcosystemNuGet},
	"npm":      {"*": osvschema.EcosystemNPM},
	"composer": {"*": osvschema.EcosystemPackagist},
	"generic":  {"*": osvschema.EcosystemOSSFuzz},
	"pypi":     {"*": osvschema.EcosystemPyPI},
	"gem":      {"*": osvschema.EcosystemRubyGems},
}

func getPURLEcosystem(pkgURL packageurl.PackageURL) osvschema.Ecosystem {
	ecoMap, ok := purlEcosystems[pkgURL.Type]
	if !ok {
		return osvschema.Ecosystem("")
	}

	wildcardRes, hasWildcard := ecoMap["*"]
	if hasWildcard {
		return wildcardRes
	}

	ecosystem, ok := ecoMap[pkgURL.Namespace]
	if !ok {
		return osvschema.Ecosystem("")
	}

	return ecosystem
}

// ToPackage converts a Package URL string to models.PackageInfo
func ToPackage(purl string) (models.PackageInfo, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return models.PackageInfo{}, err
	}
	ecosystem := getPURLEcosystem(parsedPURL)

	// PackageInfo expects the full namespace in the name for ecosystems that specify it.
	name := parsedPURL.Name
	if parsedPURL.Namespace != "" {
		switch ecosystem {
		case osvschema.EcosystemMaven:
			// Maven uses : to separate namespace and package
			name = parsedPURL.Namespace + ":" + parsedPURL.Name
		case osvschema.EcosystemDebian, osvschema.EcosystemAlpine, osvschema.EcosystemUbuntu:
			// Debian and Alpine repeats their namespace in PURL, so don't add it to the name
			name = parsedPURL.Name
		default:
			name = parsedPURL.Namespace + "/" + parsedPURL.Name
		}
	}

	return models.PackageInfo{
		Name:      name,
		Ecosystem: string(ecosystem),
		Version:   parsedPURL.Version,
	}, nil
}
