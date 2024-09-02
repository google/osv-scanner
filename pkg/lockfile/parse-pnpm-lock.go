package lockfile

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/internal/cachedregexp"
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

type PnpmLockDependency struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type PnpmLockPackages map[string]PnpmLockPackage
type PnpmSpecifiers map[string]string
type PnpmDependencies map[string]PnpmLockDependency

type PnpmImporters struct {
	Dot struct {
		Dependencies         PnpmDependencies `yaml:"dependencies,omitempty"`
		OptionalDependencies PnpmDependencies `yaml:"optionalDependencies,omitempty"`
		DevDependencies      PnpmDependencies `yaml:"devDependencies,omitempty"`
	} `yaml:".,omitempty"`
}

type PnpmLockfile struct {
	Version              string           `yaml:"lockfileVersion"`
	Packages             PnpmLockPackages `yaml:"packages,omitempty"`
	Specifiers           PnpmSpecifiers   `yaml:"specifiers,omitempty"`
	Dependencies         PnpmDependencies `yaml:"dependencies,omitempty"`
	OptionalDependencies PnpmDependencies `yaml:"optionalDependencies,omitempty"`
	DevDependencies      PnpmDependencies `yaml:"devDependencies,omitempty"`
	Importers            PnpmImporters    `yaml:"importers,omitempty"`
}

func (pnpmDependencies *PnpmDependencies) UnmarshalYAML(value *yaml.Node) error {
	if *pnpmDependencies == nil {
		*pnpmDependencies = make(map[string]PnpmLockDependency)
	}

	for i := 0; i < len(value.Content); i += 2 {
		var pnpmLockDependency PnpmLockDependency
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		// lockfileVersion >6.0
		if valueNode.Kind == yaml.MappingNode {
			if err := valueNode.Decode(&pnpmLockDependency); err != nil {
				return err
			}
		} else {
			pnpmLockDependency.Version = valueNode.Value
		}

		(*pnpmDependencies)[keyNode.Value] = pnpmLockDependency
	}

	return nil
}

const PnpmEcosystem = NpmEcosystem

func startsWithNumber(str string) bool {
	matcher := cachedregexp.MustCompile(`^\d`)

	return matcher.MatchString(str)
}

// extractPnpmPackageNameAndVersion parses a dependency path, attempting to
// extract the name and version of the package it represents
func extractPnpmPackageNameAndVersion(dependencyPath string, lockfileVersion string) (string, string) {
	// file dependencies must always have a name property to be installed,
	// and their dependency path never has the version encoded, so we can
	// skip trying to extract either from their dependency path
	if strings.HasPrefix(dependencyPath, "file:") {
		return "", ""
	}

	// v9.0 specifies the dependencies as <package>@<version> rather than as a path
	if lockfileVersion == "9.0" {
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

	if len(parts) == 0 {
		// Seems path is not complete (or at least the version is not in the path)
		// TODO : Investigate when it can happen, this is to stabilize the situation
		return "", ""
	}

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

func sanitizeLocalDependencyPath(value string, prefix string) string {
	if strings.HasPrefix(value, prefix+":") {
		value = strings.TrimPrefix(value, prefix+":")
		// Current dir locations may include an initial './'
		return strings.TrimPrefix(value, "./")
	}

	return value
}

func getVersionInfo(name string, maps ...map[string]PnpmLockDependency) (specifier, version string, found bool) {
	for _, m := range maps {
		if info, ok := m[name]; ok {
			return info.Specifier, info.Version, true
		}
	}

	return "", "", false
}

func parsePnpmLock(lockfile PnpmLockfile) []PackageDetails {
	packages := make([]PackageDetails, 0, len(lockfile.Packages))

	for s, pkg := range lockfile.Packages {
		name, version := extractPnpmPackageNameAndVersion(s, lockfile.Version)

		// Extract right part of key to then match the specifier
		var lastIndex int
		lockfileVersion, _ := strconv.ParseFloat(strings.ReplaceAll(lockfile.Version, "-flavoured", ""), 32)
		if lockfileVersion >= 6.0 {
			lastIndex = strings.LastIndex(s, "@")
		} else {
			lastIndex = strings.LastIndex(s, "/")
		}
		right := s[lastIndex+1:]

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

		var depGroups []string
		if pkg.Dev {
			depGroups = append(depGroups, "dev")
		}

		var targetVersions []string
		var targetVersion string
		var dependencyVersion string

		// Find target and dependency version
		if sp, ok := lockfile.Specifiers[name]; ok {
			// lockfile version <6.0
			targetVersion = sp
			dependencyVersion = ""
			if _, v, f := getVersionInfo(name, lockfile.Dependencies, lockfile.OptionalDependencies, lockfile.DevDependencies); f {
				dependencyVersion = v
			}
		} else if sp, v, f := getVersionInfo(name, lockfile.Dependencies, lockfile.Importers.Dot.Dependencies, lockfile.Importers.Dot.OptionalDependencies, lockfile.Importers.Dot.DevDependencies); f {
			// lockfile version >6.0
			targetVersion = sp
			dependencyVersion = v
		}

		// Sanitize the target/dependency version
		prefixes := []string{"file", "link", "portal"}
		for _, prefix := range prefixes {
			targetVersion = sanitizeLocalDependencyPath(targetVersion, prefix)
			dependencyVersion = sanitizeLocalDependencyPath(dependencyVersion, prefix)
		}

		// Multiple versions of the same dependency -> We want to set the
		// target versions only for the one included in the dependencies map
		if strings.Contains(dependencyVersion, right) {
			targetVersions = []string{targetVersion}
		}

		packages = append(packages, PackageDetails{
			Name:           name,
			Version:        version,
			TargetVersions: targetVersions,
			PackageManager: models.Pnpm,
			Ecosystem:      PnpmEcosystem,
			CompareAs:      PnpmEcosystem,
			Commit:         commit,
			DepGroups:      depGroups,
		})
	}

	return packages
}

type PnpmLockExtractor struct {
	WithMatcher
}

func (e PnpmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pnpm-lock.yaml"
}

func (e PnpmLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *PnpmLockfile

	err := yaml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	// this will happen if the file is empty
	if parsedLockfile == nil {
		parsedLockfile = &PnpmLockfile{}
	}

	return parsePnpmLock(*parsedLockfile), nil
}

var PnpmExtractor = PnpmLockExtractor{
	WithMatcher{Matcher: PackageJSONMatcher{}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("pnpm-lock.yaml", PnpmExtractor)
}

func ParsePnpmLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, PnpmExtractor)
}
