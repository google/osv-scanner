package lockfile

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scanner/pkg/models"
)

type PoetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type PoetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Source   PoetryLockPackageSource `toml:"source"`
	models.FilePosition
}

type PoetryLockFile struct {
	Version  int                  `toml:"version"`
	Packages []*PoetryLockPackage `toml:"package"`
}

const PoetryEcosystem = PipEcosystem

type PoetryLockExtractor struct{}

func (e PoetryLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "poetry.lock"
}

func (e PoetryLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *PoetryLockFile

	content, err := OpenLocalDepFile(f.Path())
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	var lines []string
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	decoder := toml.NewDecoder(strings.NewReader(strings.Join(lines, "\n")))

	if _, err := decoder.Decode(&parsedLockfile); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not decode toml from %s: %w", f.Path(), err)
	}

	fileposition.InTOML("[[package]]", "[metadata]", parsedLockfile.Packages, lines)

	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := PackageDetails{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Commit:    lockPackage.Source.Commit,
			Line:      lockPackage.Line,
			Column:    lockPackage.Column,
			Ecosystem: PoetryEcosystem,
			CompareAs: PoetryEcosystem,
		}
		if lockPackage.Optional {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, "optional")
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

var _ Extractor = PoetryLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("poetry.lock", PoetryLockExtractor{})
}

func ParsePoetryLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, PoetryLockExtractor{})
}
