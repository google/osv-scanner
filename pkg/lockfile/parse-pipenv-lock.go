package lockfile

import (
	"encoding/json"
	"fmt"
	"github.com/google/osv-scanner/pkg/models"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

const PipenvEcosystem = PipEcosystem

type PipenvLockExtractor struct{}

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

func (e PipenvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile PipenvLock

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

	key := ""
	packageType := ""

	for i, line := range lines {
		startRe := regexp.MustCompile(`"(\w+)": {`)
		startMatch := startRe.FindStringSubmatch(line)

		if len(startMatch) == 2 {
			key = startMatch[1]

			if key == "default" {
				packageType = "packages"
			} else if key == "develop" {
				packageType = "packages-dev"
			}

			if packageType != "" {
				switch packageType {
				case "packages":
					dep := parsedLockfile.Packages[key]
					dep.Start = models.FilePosition{Line: i + 1}
					parsedLockfile.Packages[key] = dep
					break
				case "packages-dev":
					dep := parsedLockfile.PackagesDev[key]
					dep.Start = models.FilePosition{Line: i + 1}
					parsedLockfile.PackagesDev[key] = dep
					break
				}
			}
		}

		if len(key) != 0 && strings.Contains(line, "}") {
			switch packageType {
			case "packages":
				dep := parsedLockfile.Packages[key]
				dep.End = models.FilePosition{Line: i + 1}
				parsedLockfile.Packages[key] = dep
				break
			case "packages-dev":
				dep := parsedLockfile.PackagesDev[key]
				dep.End = models.FilePosition{Line: i + 1}
				parsedLockfile.PackagesDev[key] = dep
				break
			}
			key = ""
		}
	}

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
