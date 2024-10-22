package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type ConanReference struct {
	Name            string
	Version         string
	Username        string
	Channel         string
	RecipeRevision  string
	PackageID       string
	PackageRevision string
	TimeStamp       string
}

type ConanGraphNode struct {
	Pref      string `json:"pref"`
	Ref       string `json:"ref"`
	Options   string `json:"options"`
	PackageID string `json:"package_id"`
	Prev      string `json:"prev"`
	Path      string `json:"path"`
	Context   string `json:"context"`
}

type ConanGraphLock struct {
	Nodes map[string]ConanGraphNode `json:"nodes"`
}

type ConanLockFile struct {
	Version string `json:"version"`
	// conan v0.4- lockfiles use "graph_lock", "profile_host" and "profile_build"
	GraphLock    ConanGraphLock `json:"graph_lock,omitempty"`
	ProfileHost  string         `json:"profile_host,omitempty"`
	ProfileBuild string         `json:"profile_build,omitempty"`
	// conan v0.5+ lockfiles use "requires", "build_requires" and "python_requires"
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
}

// TODO this is tentative and subject to change depending on the OSV schema
const ConanEcosystem Ecosystem = "ConanCenter"

func parseConanReference(ref string) ConanReference {
	// very flexible format name/version[@username[/channel]][#rrev][:pkgid[#prev]][%timestamp]
	var reference ConanReference

	parts := strings.SplitN(ref, "%", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.TimeStamp = parts[1]
	}

	parts = strings.SplitN(ref, ":", 2)
	if len(parts) == 2 {
		ref = parts[0]
		parts = strings.SplitN(parts[1], "#", 2)
		reference.PackageID = parts[0]
		if len(parts) == 2 {
			reference.PackageRevision = parts[1]
		}
	}

	parts = strings.SplitN(ref, "#", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.RecipeRevision = parts[1]
	}

	parts = strings.SplitN(ref, "@", 2)
	if len(parts) == 2 {
		ref = parts[0]
		UsernameChannel := parts[1]

		parts = strings.SplitN(UsernameChannel, "/", 2)
		reference.Username = parts[0]
		if len(parts) == 2 {
			reference.Channel = parts[1]
		}
	}

	parts = strings.SplitN(ref, "/", 2)
	if len(parts) == 2 {
		reference.Name = parts[0]
		reference.Version = parts[1]
	} else {
		// consumer conanfile.txt or conanfile.py might not have a name
		reference.Name = ""
		reference.Version = ref
	}

	return reference
}

func parseConanV1Lock(lockfile ConanLockFile) []PackageDetails {
	var reference ConanReference
	packages := make([]PackageDetails, 0, len(lockfile.GraphLock.Nodes))

	for _, node := range lockfile.GraphLock.Nodes {
		if node.Path != "" {
			// a local "conanfile.txt", skip
			continue
		}

		if node.Pref != "" {
			// old format 0.3 (conan 1.27-) lockfiles use "pref" instead of "ref"
			reference = parseConanReference(node.Pref)
		} else if node.Ref != "" {
			reference = parseConanReference(node.Ref)
		} else {
			continue
		}
		// skip entries with no name, they are most likely consumer's conanfiles
		// and not dependencies to be searched in a database anyway
		if reference.Name == "" {
			continue
		}
		packages = append(packages, PackageDetails{
			Name:      reference.Name,
			Version:   reference.Version,
			Ecosystem: ConanEcosystem,
			CompareAs: ConanEcosystem,
		})
	}

	return packages
}

func parseConanRequires(packages *[]PackageDetails, requires []string, group string) {
	for _, ref := range requires {
		reference := parseConanReference(ref)
		// skip entries with no name, they are most likely consumer's conanfiles
		// and not dependencies to be searched in a database anyway
		if reference.Name == "" {
			continue
		}

		*packages = append(*packages, PackageDetails{
			Name:      reference.Name,
			Version:   reference.Version,
			Ecosystem: ConanEcosystem,
			CompareAs: ConanEcosystem,
			DepGroups: []string{group},
		})
	}
}

func parseConanV2Lock(lockfile ConanLockFile) []PackageDetails {
	packages := make(
		[]PackageDetails,
		0,
		uint64(len(lockfile.Requires))+uint64(len(lockfile.BuildRequires))+uint64(len(lockfile.PythonRequires)),
	)

	parseConanRequires(&packages, lockfile.Requires, "requires")
	parseConanRequires(&packages, lockfile.BuildRequires, "build-requires")
	parseConanRequires(&packages, lockfile.PythonRequires, "python-requires")

	return packages
}

func parseConanLock(lockfile ConanLockFile) []PackageDetails {
	if lockfile.GraphLock.Nodes != nil {
		return parseConanV1Lock(lockfile)
	}

	return parseConanV2Lock(lockfile)
}

type ConanLockExtractor struct{}

func (e ConanLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "conan.lock"
}

func (e ConanLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *ConanLockFile

	err := json.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	return parseConanLock(*parsedLockfile), nil
}

var _ Extractor = ConanLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("conan.lock", ConanLockExtractor{})
}

// Deprecated: use ConanLockExtractor.Extract instead
func ParseConanLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, ConanLockExtractor{})
}
