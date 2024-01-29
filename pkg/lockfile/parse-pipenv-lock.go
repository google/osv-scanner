package lockfile

import (
	"encoding/json"
	"fmt"
	"github.com/google/osv-scanner/internal/cachedregexp"
	"os"
	"path/filepath"
	"strings"

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

func findPackagesLinePosition(groupMap map[string]map[string]PipenvPackage, lines []string) {
	var group, key string
	var groupLevel, stack int
	for lineNumber, line := range lines {
		if strings.Contains(line, "{") {
			stack++
			keyRegexp := cachedregexp.MustCompile(`"(.+)"`)
			match := keyRegexp.FindStringSubmatch(line)
			if len(match) == 2 {
				key = match[1]
				if group != "" {
					dep := groupMap[group][key]
					dep.Start = models.FilePosition{Line: lineNumber + 1}
					groupMap[group][key] = dep
				} else {
					for groupKey := range groupMap {
						if groupKey == key {
							group = key
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
					dep := groupMap[group][key]
					dep.End = models.FilePosition{Line: lineNumber + 1}
					groupMap[group][key] = dep
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

	groupMap := make(map[string]map[string]PipenvPackage)
	groupMap[packages] = parsedLockfile.Packages
	groupMap[packagesDev] = parsedLockfile.PackagesDev
	findPackagesLinePosition(groupMap, lines)

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
