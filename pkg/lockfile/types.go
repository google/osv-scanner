package lockfile

import "github.com/google/osv-scanner/pkg/models"

// TODO(v2): These fields do not need JSON tags I believe
type PackageDetails struct {
	Name        string                     `json:"name"`
	Version     string                     `json:"version"`
	Commit      string                     `json:"commit,omitempty"`
	Ecosystem   Ecosystem                  `json:"ecosystem,omitempty"`
	CompareAs   Ecosystem                  `json:"compareAs,omitempty"`
	DepGroups   []string                   `json:"depGroups,omitempty"`
	ImageOrigin *models.ImageOriginDetails `json:"imageOrigin,omitempty"`
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func (sys Ecosystem) IsDevGroup(groups []string) bool {
	dev := ""
	switch sys {
	case ComposerEcosystem, NpmEcosystem, PipEcosystem, PubEcosystem:
		// Also PnpmEcosystem(=NpmEcosystem) and PipenvEcosystem(=PipEcosystem).
		dev = "dev"
	case ConanEcosystem:
		dev = "build-requires"
	case MavenEcosystem:
		dev = "test"
	case AlpineEcosystem, BundlerEcosystem, CargoEcosystem, CRANEcosystem,
		DebianEcosystem, GoEcosystem, MixEcosystem, NuGetEcosystem:
		// We are not able to report development dependencies for these ecosystems.
		return false
	}

	for _, g := range groups {
		if g == dev {
			return true
		}
	}

	return false
}
