// Package purl provides functionality for working with PURLs.
package purl

import (
	"fmt"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

type ParameterExtractor func(packageInfo models.PackageInfo) (namespace string, name string, err error)

var EcosystemToPURLMapper = map[osvconstants.Ecosystem]string{
	osvconstants.EcosystemMaven:       packageurl.TypeMaven,
	osvconstants.EcosystemGo:          packageurl.TypeGolang,
	osvconstants.EcosystemPackagist:   packageurl.TypeComposer,
	osvconstants.EcosystemPyPI:        packageurl.TypePyPi,
	osvconstants.EcosystemRubyGems:    packageurl.TypeGem,
	osvconstants.EcosystemNuGet:       packageurl.TypeNuget,
	osvconstants.EcosystemNPM:         packageurl.TypeNPM,
	osvconstants.EcosystemConanCenter: packageurl.TypeConan,
	osvconstants.EcosystemCratesIO:    packageurl.TypeCargo,
	osvconstants.EcosystemPub:         packageurl.TypePub,
	osvconstants.EcosystemHex:         packageurl.TypeHex,
	osvconstants.EcosystemCRAN:        packageurl.TypeCran,
}

var ecosystemPURLExtractor = map[osvconstants.Ecosystem]ParameterExtractor{
	osvconstants.EcosystemMaven:     FromMaven,
	osvconstants.EcosystemGo:        FromGo,
	osvconstants.EcosystemPackagist: FromComposer,
}

func FromPackage(packageInfo models.PackageInfo) (*packageurl.PackageURL, error) {
	var namespace string
	var name string
	version := packageInfo.Version
	eco, err := osvecosystem.Parse(packageInfo.Ecosystem)
	if err != nil {
		return nil, err
	}
	purlType, typeExists := EcosystemToPURLMapper[eco.Ecosystem]
	parameterExtractor, extractorExists := ecosystemPURLExtractor[eco.Ecosystem]

	if !typeExists {
		return nil, fmt.Errorf("unable to determine purl type of %s@%s (%s)", packageInfo.Name, packageInfo.Version, packageInfo.Ecosystem)
	}

	if extractorExists {
		var err error
		namespace, name, err = parameterExtractor(packageInfo)
		if err != nil {
			return nil, err
		}
	} else {
		name = packageInfo.Name
	}

	return packageurl.NewPackageURL(purlType, namespace, name, version, nil, ""), nil
}
