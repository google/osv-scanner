package lockfile

import (
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

type PackageDetails struct {
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	TargetVersions  []string              `json:"targetVersions,omitempty"`
	Commit          string                `json:"commit,omitempty"`
	Ecosystem       Ecosystem             `json:"ecosystem,omitempty"`
	CompareAs       Ecosystem             `json:"compareAs,omitempty"`
	DepGroups       []string              `json:"-"`
	BlockLocation   models.FilePosition   `json:"blockLocation,omitempty"`
	VersionLocation *models.FilePosition  `json:"versionLocation,omitempty"`
	NameLocation    *models.FilePosition  `json:"nameLocation,omitempty"`
	PackageManager  models.PackageManager `json:"packageManager,omitempty"`
	IsDirect        bool                  `json:"isDirect,omitempty"`
}

type Ecosystem string

type DepGroup string

const (
	DepGroup_Prod DepGroup = "prod"
	DepGroup_Dev  DepGroup = "dev"
)

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func (sys Ecosystem) IsDevGroup(groups []string) bool {
	switch sys {
	case NpmEcosystem:
		return sys.isNpmDevGroup(groups)
	case ComposerEcosystem, PipEcosystem, PubEcosystem, NuGetEcosystem:
		// Also PnpmEcosystem(=NpmEcosystem) and PipenvEcosystem(=PipEcosystem,=PoetryEcosystem).
		return sys.isDevGroup(groups, string(DepGroup_Dev))
	case ConanEcosystem:
		return sys.isDevGroup(groups, "build-requires")
	case MavenEcosystem:
		return sys.isMavenDevGroup(groups)
	case AlpineEcosystem, DebianEcosystem, CargoEcosystem, BundlerEcosystem, GoEcosystem, MixEcosystem, CRANEcosystem:
		return false
	}

	return false
}

// isMavenDevGroup defines whether the dependency is only present in tests for the maven ecosystem or not (Maven and Gradle).
func (sys Ecosystem) isMavenDevGroup(groups []string) bool {
	if len(groups) == 0 {
		return false
	}

	for _, g := range groups {
		if !strings.HasPrefix(g, "test") {
			return false
		}
	}

	return true
}

func (sys Ecosystem) isNpmDevGroup(groups []string) bool {
	containsDev := false

	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if g != "dev" && g != "optional" {
			return false
		} else if g == "dev" {
			containsDev = true
		}
	}

	return containsDev
}

func (sys Ecosystem) isDevGroup(groups []string, devGroupName string) bool {
	if len(groups) == 0 {
		return false
	}

	for _, g := range groups {
		if g != devGroupName {
			return false
		}
	}

	return true
}

func (pkg PackageDetails) IsVersionEmpty() bool {
	return pkg.Version == ""
}
