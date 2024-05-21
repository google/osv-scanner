package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"

	"github.com/google/osv-scanner/pkg/models"
)

type PipenvPackage struct {
	Version string `json:"version"`
	models.FilePosition
	NamePosition    *models.FilePosition
	VersionPosition *models.FilePosition
}

type PipenvLock struct {
	Packages    map[string]*PipenvPackage `json:"default"`
	PackagesDev map[string]*PipenvPackage `json:"develop"`
}

const PipenvEcosystem = PipEcosystem

type PipenvLockExtractor struct{}

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

func (e PipenvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *PipenvLock

	content, err := OpenLocalDepFile(f.Path())
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}
	contentString := string(contentBytes)
	lines := strings.Split(contentString, "\n")
	decoder := json.NewDecoder(strings.NewReader(contentString))

	if err := decoder.Decode(&parsedLockfile); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not decode json from %s: %w", f.Path(), err)
	}

	fileposition.InJSON("default", parsedLockfile.Packages, lines, 0)
	fileposition.InJSON("develop", parsedLockfile.PackagesDev, lines, 0)

	extractNameAndVersionPosition(lines, parsedLockfile.Packages)
	extractNameAndVersionPosition(lines, parsedLockfile.PackagesDev)

	details := make(map[string]PackageDetails)

	addPkgDetails(details, parsedLockfile.Packages, "", f.Path())
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev", f.Path())

	return pkgDetailsMapToSlice(details), nil
}

func extractNameAndVersionPosition(lines []string, packages map[string]*PipenvPackage) {
	namePrefix := `"`
	nameSuffix := `": {`

	versionPrefix := `"version": "`
	versionSuffix := `"`

	for name, pipenvPackage := range packages {
		blockLine := lines[pipenvPackage.Line.Start-1 : pipenvPackage.Line.End]

		pipenvPackage.NamePosition = fileposition.ExtractDelimitedStringPositionInBlock(blockLine, name, pipenvPackage.Line.Start, namePrefix, nameSuffix)
		pipenvPackage.VersionPosition = fileposition.ExtractDelimitedStringPositionInBlock(blockLine, pipenvPackage.Version, pipenvPackage.Line.Start, versionPrefix, versionSuffix)
	}
}

func addPkgDetails(details map[string]PackageDetails, packages map[string]*PipenvPackage, group string, path string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		blockLocation := models.FilePosition{
			Line:     pipenvPackage.Line,
			Column:   pipenvPackage.Column,
			Filename: path,
		}
		pipenvPackage.NamePosition.Filename = path
		pipenvPackage.VersionPosition.Filename = path

		if _, ok := details[name+"@"+version]; !ok {
			pkgDetails := PackageDetails{
				Name:            name,
				Version:         version,
				Ecosystem:       PipenvEcosystem,
				CompareAs:       PipenvEcosystem,
				BlockLocation:   blockLocation,
				NameLocation:    pipenvPackage.NamePosition,
				VersionLocation: pipenvPackage.VersionPosition,
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
