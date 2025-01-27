package semantic

import (
	"errors"
	"fmt"

	"github.com/google/osv-scanner/pkg/models"
)

var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")

var ErrUnknownEcosystem = errors.New("unknown ecosystem")

func MustParse(str string, ecosystem models.Ecosystem) Version {
	v, err := Parse(str, ecosystem)

	if err != nil {
		panic(err)
	}

	return v
}

func Parse(str string, ecosystem models.Ecosystem) (Version, error) {
	var version Version
	var err error

	switch ecosystem {
	case models.EcosystemNPM:
		version = parseSemverVersion(str)
	case models.EcosystemCratesIO:
		version = parseSemverVersion(str)
	case models.EcosystemDebian:
		version = parseDebianVersion(str)
	case models.EcosystemAlpine:
		version = parseAlpineVersion(str)
	case models.EcosystemRubyGems:
		version = parseRubyGemsVersion(str)
	case models.EcosystemNuGet:
		version = parseNuGetVersion(str)
	case models.EcosystemPackagist:
		version = parsePackagistVersion(str)
	case models.EcosystemGo:
		version = parseSemverVersion(str)
	case models.EcosystemHex:
		version = parseSemverVersion(str)
	case models.EcosystemMaven:
		version = parseMavenVersion(str)
	case models.EcosystemPyPI:
		version = parsePyPIVersion(str)
	case models.EcosystemPub:
		version = parseSemverVersion(str)
	case models.EcosystemConanCenter:
		version = parseSemverVersion(str)
	case models.EcosystemCRAN:
		version = parseCRANVersion(str)
	case models.EcosystemOSSFuzz, models.EcosystemLinux, models.EcosystemAndroid, models.EcosystemGitHubActions, models.EcosystemRockyLinux, models.EcosystemAlmaLinux, models.EcosystemBitnami, models.EcosystemPhotonOS, models.EcosystemBioconductor, models.EcosystemSwiftURL:
		err = fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
	default:
		err = fmt.Errorf("%w %s", ErrUnknownEcosystem, ecosystem)
	}

	return version, err
}
