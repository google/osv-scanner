package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"

	"github.com/google/osv-scanner/pkg/models"
)

type PipenvPackage struct {
	Version string `json:"version"`
	Start   models.FilePosition
	End     models.FilePosition
}

type PipenvLock struct {
	Packages    map[string]PipenvPackage `json:"default"`
	PackagesDev map[string]PipenvPackage `json:"develop"`
}

const (
	packages    = "default"
	packagesDev = "develop"
)

const PipenvEcosystem = PipEcosystem

type PipenvLockExtractor struct{}

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

// This function set the line location of a package within the file by updating the Start/End variables
// for each of the PipenvPackages of each the groups in the groups map.
// "groupsMap" contains different groups of packages. Each group contains different PipenvPackage
// "groupsMap" keys MUST be the same ones as the JSON group keys (check PipenvLock struct)
func findPackagesLinePosition(groupsMap map[string]map[string]PipenvPackage, lines []string) {
	var group, dependency string
	var groupLevel, stack int
	for lineNumber, line := range lines {
		if strings.Contains(line, "{") {
			stack++
			keyRegexp := cachedregexp.MustCompile(`"(.+)"`)
			match := keyRegexp.FindStringSubmatch(line)
			if len(match) == 2 {
				dependency = match[1]
				if group != "" && stack == groupLevel+1 {
					dep := groupsMap[group][dependency]
					dep.Start = models.FilePosition{Line: lineNumber + 1}
					groupsMap[group][dependency] = dep
				} else {
					for groupKey := range groupsMap {
						if groupKey == dependency {
							group = dependency
							groupLevel = stack

							break
						}
					}
				}
			}
		}
		if strings.Contains(line, "}") {
			stack--
			if group != "" {
				if stack == groupLevel {
					dep := groupsMap[group][dependency]
					dep.End = models.FilePosition{Line: lineNumber + 1}
					groupsMap[group][dependency] = dep
					dependency = ""
				} else if stack == groupLevel-1 {
					group = ""
				}
			}
		}
	}
}

func (e PipenvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *PipenvLock

	content, err := os.ReadFile(f.Path())
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	contentString := string(content)
	lines := strings.Split(contentString, "\n")
	decoder := json.NewDecoder(strings.NewReader(contentString))

	if err := decoder.Decode(&parsedLockfile); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not decode json from %s: %w", f.Path(), err)
	}

	groupsMap := make(map[string]map[string]PipenvPackage)
	groupsMap[packages] = parsedLockfile.Packages
	groupsMap[packagesDev] = parsedLockfile.PackagesDev
	findPackagesLinePosition(groupsMap, lines)

	details := make(map[string]PackageDetails)

	addPkgDetails(details, parsedLockfile.Packages, "")
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev")

	return pkgDetailsMapToSlice(details), nil
}

func addPkgDetails(details map[string]PackageDetails, packages map[string]PipenvPackage, group string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		if _, ok := details[name+"@"+version]; !ok {
			pkgDetails := PackageDetails{
				Name:      name,
				Version:   version,
				Start:     pipenvPackage.Start,
				End:       pipenvPackage.End,
				Ecosystem: PipenvEcosystem,
				CompareAs: PipenvEcosystem,
			}
			if group != "" {
				pkgDetails.DepGroups = append(pkgDetails.DepGroups, group)
			}
			details[name+"@"+version] = pkgDetails
		}
	}
}

var _ Extractor = PipenvLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("Pipfile.lock", PipenvLockExtractor{})
}

func ParsePipenvLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, PipenvLockExtractor{})
}
