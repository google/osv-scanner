// Package purl provides functionality for working with PURLs.
package purl

import (
	"fmt"

	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/package-url/packageurl-go"
)

type ParameterExtractor func(packageInfo models.PackageInfo) (namespace string, name string, err error)

var EcosystemToPURLMapper = map[osvschema.Ecosystem]string{
	osvschema.EcosystemMaven:       packageurl.TypeMaven,
	osvschema.EcosystemGo:          packageurl.TypeGolang,
	osvschema.EcosystemPackagist:   packageurl.TypeComposer,
	osvschema.EcosystemPyPI:        packageurl.TypePyPi,
	osvschema.EcosystemRubyGems:    packageurl.TypeGem,
	osvschema.EcosystemNuGet:       packageurl.TypeNuget,
	osvschema.EcosystemNPM:         packageurl.TypeNPM,
	osvschema.EcosystemConanCenter: packageurl.TypeConan,
	osvschema.EcosystemCratesIO:    packageurl.TypeCargo,
	osvschema.EcosystemPub:         packageurl.TypePub,
	osvschema.EcosystemHex:         packageurl.TypeHex,
	osvschema.EcosystemCRAN:        packageurl.TypeCran,
}

var ecosystemPURLExtractor = map[osvschema.Ecosystem]ParameterExtractor{
	osvschema.EcosystemMaven:     FromMaven,
	osvschema.EcosystemGo:        FromGo,
	osvschema.EcosystemPackagist: FromComposer,
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
