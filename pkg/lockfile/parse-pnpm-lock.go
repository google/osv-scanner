package lockfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

type PnpmLockPackageResolution struct {
	Tarball string `yaml:"tarball"`
	Commit  string `yaml:"commit"`
	Repo    string `yaml:"repo"`
	Type    string `yaml:"type"`
}

type PnpmLockPackage struct {
	Resolution PnpmLockPackageResolution `yaml:"resolution"`
	Name       string                    `yaml:"name"`
	Version    string                    `yaml:"version"`
	Dev        bool                      `yaml:"dev"`
}

type PnpmLockfile struct {
	Version  float64                    `yaml:"lockfileVersion"`
	Packages map[string]PnpmLockPackage `yaml:"packages,omitempty"`
}

type pnpmLockfileV6 struct {
	Version  string                     `yaml:"lockfileVersion"`
	Packages map[string]PnpmLockPackage `yaml:"packages,omitempty"`
}

func (l *PnpmLockfile) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var lockfileV6 pnpmLockfileV6

	if err := unmarshal(&lockfileV6); err != nil {
		return err
	}

	parsedVersion, err := strconv.ParseFloat(lockfileV6.Version, 64)

	if err != nil {
		return err
	}

	l.Version = parsedVersion
	l.Packages = lockfileV6.Packages

	return nil
}

const PnpmEcosystem = NpmEcosystem

func startsWithNumber(str string) bool {
	matcher := cachedregexp.MustCompile(`^\d`)

	return matcher.MatchString(str)
}

// extractPnpmPackageNameAndVersion parses a dependency path, attempting to
// extract the name and version of the package it represents
func extractPnpmPackageNameAndVersion(dependencyPath string, lockfileVersion float64) (string, string) {
	// file dependencies must always have a name property to be installed,
	// and their dependency path never has the version encoded, so we can
	// skip trying to extract either from their dependency path
	if strings.HasPrefix(dependencyPath, "file:") {
		return "", ""
	}

	// v9.0 specifies the dependencies as <package>@<version> rather than as a path
	if lockfileVersion == 9.0 {
		dependencyPath = strings.Trim(dependencyPath, "'")
		dependencyPath, isScoped := strings.CutPrefix(dependencyPath, "@")

		name, version, _ := strings.Cut(dependencyPath, "@")

		if isScoped {
			name = "@" + name
		}

		return name, version
	}

	parts := strings.Split(dependencyPath, "/")
	var name string

	parts = parts[1:]

	if strings.HasPrefix(parts[0], "@") {
		name = strings.Join(parts[:2], "/")
		parts = parts[2:]
	} else {
		name = parts[0]
		parts = parts[1:]
	}

	version := ""

	if len(parts) != 0 {
		version = parts[0]
	}

	if version == "" {
		name, version = parseNameAtVersion(name)
	}

	if version == "" || !startsWithNumber(version) {
		return "", ""
	}

	underscoreIndex := strings.Index(version, "_")

	if underscoreIndex != -1 {
		version = strings.Split(version, "_")[0]
	}

	return name, version
}

func parseNameAtVersion(value string) (name string, version string) {
	// look for pattern "name@version", where name is allowed to contain zero or more "@"
	matches := cachedregexp.MustCompile(`^(.+)@([\d.]+)$`).FindStringSubmatch(value)

	if len(matches) != 3 {
		return name, ""
	}

	return matches[1], matches[2]
}

func parsePnpmLock(lockfile PnpmLockfile) []*Inventory {
	packages := make([]*Inventory, 0, len(lockfile.Packages))

	for s, pkg := range lockfile.Packages {
		name, version := extractPnpmPackageNameAndVersion(s, lockfile.Version)

		// "name" is only present if it's not in the dependency path and takes
		// priority over whatever name we think we've extracted (if any)
		if pkg.Name != "" {
			name = pkg.Name
		}

		// "version" is only present if it's not in the dependency path and takes
		// priority over whatever version we think we've extracted (if any)
		if pkg.Version != "" {
			version = pkg.Version
		}

		if name == "" || version == "" {
			continue
		}

		commit := pkg.Resolution.Commit

		if strings.HasPrefix(pkg.Resolution.Tarball, "https://codeload.github.com") {
			re := cachedregexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
			matched := re.FindStringSubmatch(pkg.Resolution.Tarball)

			if matched != nil {
				commit = matched[1]
			}
		}

		depGroups := []string{}
		if pkg.Dev {
			depGroups = append(depGroups, "dev")
		}

		packages = append(packages, &Inventory{
			Name:    name,
			Version: version,
			SourceCode: &SourceCodeIdentifier{
				Commit: commit,
			},
			Metadata: DepGroupMetadata{
				DepGroupVals: depGroups,
			},
		})
	}

	return packages
}

type PnpmLockExtractor struct{}

// Name of the extractor
func (e PnpmLockExtractor) Name() string { return "javascript/pnpmlock" }

// Version of the extractor
func (e PnpmLockExtractor) Version() int { return 0 }

func (e PnpmLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e PnpmLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "pnpm-lock.yaml"
}

func (e PnpmLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *PnpmLockfile

	err := yaml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	// this will happen if the file is empty
	if parsedLockfile == nil {
		parsedLockfile = &PnpmLockfile{}
	}

	inventories := parsePnpmLock(*parsedLockfile)
	for i := range inventories {
		inventories[i].Locations = []string{input.Path}
	}

	return inventories, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e PnpmLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeNPM,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e PnpmLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e PnpmLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case PnpmLockExtractor:
		return string(PnpmEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = PnpmLockExtractor{}
