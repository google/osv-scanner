package purl

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/package-url/packageurl-go"
)

type ParameterExtractor func(packageInfo models.PackageInfo) (namespace string, name string, err error)

var EcosystemToPURLMapper = map[models.Ecosystem]string{
	models.EcosystemMaven:       packageurl.TypeMaven,
	models.EcosystemGo:          packageurl.TypeGolang,
	models.EcosystemPackagist:   packageurl.TypeComposer,
	models.EcosystemPyPI:        packageurl.TypePyPi,
	models.EcosystemRubyGems:    packageurl.TypeGem,
	models.EcosystemNuGet:       packageurl.TypeNuget,
	models.EcosystemNPM:         packageurl.TypeNPM,
	models.EcosystemConanCenter: packageurl.TypeConan,
	models.EcosystemCratesIO:    packageurl.TypeCargo,
	models.EcosystemPub:         packageurl.TypePub,
	models.EcosystemHex:         packageurl.TypeHex,
	models.EcosystemCRAN:        packageurl.TypeCran,
}

var ecosystemPURLExtractor = map[models.Ecosystem]ParameterExtractor{
	models.EcosystemMaven:     FromMaven,
	models.EcosystemGo:        FromGo,
	models.EcosystemPackagist: FromComposer,
}

func From(packageInfo models.PackageInfo) (*packageurl.PackageURL, error) {
	var namespace string
	var name string
	version := packageInfo.Version
	ecosystem := models.Ecosystem(packageInfo.Ecosystem)
	purlType, typeExists := EcosystemToPURLMapper[ecosystem]
	parameterExtractor, extractorExists := ecosystemPURLExtractor[ecosystem]

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
