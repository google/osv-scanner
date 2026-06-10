package purl

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

// used like so: purlEcosystems[PkgURL.Type][PkgURL.Namespace]
// * means it should match any namespace string
var purlEcosystems = map[string]map[string]osvconstants.Ecosystem{
	"apk":      {"alpine": osvconstants.EcosystemAlpine},
	"cargo":    {"*": osvconstants.EcosystemCratesIO},
	"composer": {"*": osvconstants.EcosystemPackagist},
	"conan":    {"*": osvconstants.EcosystemConanCenter},
	"cran":     {"*": osvconstants.EcosystemCRAN},
	"deb": {
		"debian": osvconstants.EcosystemDebian,
		"ubuntu": osvconstants.EcosystemUbuntu,
	},
	"gem": {"*": osvconstants.EcosystemRubyGems},
	// We don't yet have a GIT ecosystem which aligns with the generic type better.
	// "generic": {"*": osvconstants.EcosystemOSSFuzz},
	"github":  {"*": osvconstants.EcosystemGitHubActions},
	"golang":  {"*": osvconstants.EcosystemGo},
	"hackage": {"*": osvconstants.EcosystemHackage},
	"hex":     {"*": osvconstants.EcosystemHex},
	"k8s":     {"*": osvconstants.EcosystemKubernetes},
	"maven":   {"*": osvconstants.EcosystemMaven},
	"npm":     {"*": osvconstants.EcosystemNPM},
	"nuget":   {"*": osvconstants.EcosystemNuGet},
	"pub":     {"*": osvconstants.EcosystemPub},
	"pypi":    {"*": osvconstants.EcosystemPyPI},
	"swift":   {"*": osvconstants.EcosystemSwiftURL},
}

func getPURLEcosystem(pkgURL packageurl.PackageURL) osvconstants.Ecosystem {
	ecoMap, ok := purlEcosystems[pkgURL.Type]
	if !ok {
		return osvconstants.Ecosystem("")
	}

	wildcardRes, hasWildcard := ecoMap["*"]
	if hasWildcard {
		return wildcardRes
	}

	ecosystem, ok := ecoMap[pkgURL.Namespace]
	if !ok {
		return osvconstants.Ecosystem("")
	}

	if ecosystem == osvconstants.EcosystemAlpine {
		distro := ""
		for _, q := range pkgURL.Qualifiers {
			if q.Key == "distro" {
				distro = q.Value
				break
			}
		}
		if distro != "" {
			versionID := distro
			if idx := strings.LastIndex(distro, "-"); idx != -1 {
				versionID = distro[idx+1:]
			}
			versionID = strings.TrimLeft(versionID, "vV")

			if versionID == "edge" {
				return osvconstants.Ecosystem("Alpine:edge")
			}

			if len(versionID) > 0 && versionID[0] >= '0' && versionID[0] <= '9' {
				parts := strings.Split(versionID, ".")
				if len(parts) >= 2 {
					return osvconstants.Ecosystem(fmt.Sprintf("Alpine:v%s.%s", parts[0], parts[1]))
				}
			}
		}
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
		ecosystemBase, _, _ := strings.Cut(string(ecosystem), ":")
		switch osvconstants.Ecosystem(ecosystemBase) {
		case osvconstants.EcosystemMaven:
			// Maven uses : to separate namespace and package
			name = parsedPURL.Namespace + ":" + parsedPURL.Name
		case osvconstants.EcosystemDebian, osvconstants.EcosystemAlpine, osvconstants.EcosystemUbuntu:
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
