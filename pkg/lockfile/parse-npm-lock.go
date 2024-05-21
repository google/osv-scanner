package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"

	"github.com/google/osv-scanner/pkg/models"
)

type NpmLockDependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version      string                        `json:"version"`
	Dependencies map[string]*NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	models.FilePosition
}

func (npmLockDependency *NpmLockDependency) GetNestedDependencies() map[string]*models.FilePosition {
	result := make(map[string]*models.FilePosition)
	for key, value := range npmLockDependency.Dependencies {
		result[key] = &value.FilePosition
	}

	return result
}

type NpmLockPackage struct {
	// For an aliased package, Name is the real package name
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
	Link         bool              `json:"link,omitempty"`

	Dev         bool `json:"dev,omitempty"`
	DevOptional bool `json:"devOptional,omitempty"`
	Optional    bool `json:"optional,omitempty"`

	models.FilePosition
}

type NpmLockfile struct {
	Version    int `json:"lockfileVersion"`
	SourceFile string
	// npm v1- lockfiles use "dependencies"
	Dependencies map[string]*NpmLockDependency `json:"dependencies"`
	// npm v2+ lockfiles use "packages"
	Packages map[string]*NpmLockPackage `json:"packages,omitempty"`
}

const NpmEcosystem Ecosystem = "npm"

func pkgDetailsMapToSlice(m map[string]PackageDetails) []PackageDetails {
	details := make([]PackageDetails, 0, len(m))

	for _, detail := range m {
		details = append(details, detail)
	}

	return details
}

func mergePkgDetailsMap(m1 map[string]PackageDetails, m2 map[string]PackageDetails) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	for name, detail := range m1 {
		details[name] = detail
	}

	for name, detail := range m2 {
		if _, ok := details[name]; !ok {
			details[name] = detail
		}
	}

	return details
}

func (npmLockDependency *NpmLockDependency) depGroups() []string {
	if npmLockDependency.Dev && npmLockDependency.Optional {
		return []string{"dev", "optional"}
	}
	if npmLockDependency.Dev {
		return []string{"dev"}
	}
	if npmLockDependency.Optional {
		return []string{"optional"}
	}

	return nil
}

func parseNpmLockDependencies(dependencies map[string]*NpmLockDependency, path string) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	keys := reflect.ValueOf(dependencies).MapKeys()
	keysOrder := func(i, j int) bool { return keys[i].Interface().(string) < keys[j].Interface().(string) }
	sort.Slice(keys, keysOrder)

	for _, key := range keys {
		name := key.Interface().(string)
		detail := dependencies[name]
		if detail.Dependencies != nil {
			details = mergePkgDetailsMap(details, parseNpmLockDependencies(detail.Dependencies, path))
		}

		version := detail.Version
		finalVersion := version
		commit := ""

		// If the package is aliased, get the name and version
		if strings.HasPrefix(detail.Version, "npm:") {
			i := strings.LastIndex(detail.Version, "@")
			name = detail.Version[4:i]
			finalVersion = detail.Version[i+1:]
		}

		// we can't resolve a version from a "file:" dependency
		if strings.HasPrefix(detail.Version, "file:") {
			finalVersion = "0.0.0"
			version = "0.0.0"
		} else {
			commit = tryExtractCommit(detail.Version)

			// if there is a commit, we want to deduplicate based on that rather than
			// the version (the versions must match anyway for the commits to match)
			//
			// we also don't actually know what the "version" is, so blank it
			if commit != "" {
				finalVersion = ""
				version = commit
			}
		}

		details[name+"@"+version] = PackageDetails{
			Name:      name,
			Version:   finalVersion,
			Ecosystem: NpmEcosystem,
			CompareAs: NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     detail.Line,
				Column:   detail.Column,
				Filename: path,
			},
			Commit:    commit,
			DepGroups: detail.depGroups(),
		}
	}

	return details
}

func extractNpmPackageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

func (npmLockDependency NpmLockPackage) depGroups() []string {
	if npmLockDependency.Dev {
		return []string{"dev"}
	}
	if npmLockDependency.Optional {
		return []string{"optional"}
	}
	if npmLockDependency.DevOptional {
		return []string{"dev", "optional"}
	}

	return nil
}

func parseNpmLockPackages(packages map[string]*NpmLockPackage, path string) map[string]PackageDetails {
	details := map[string]PackageDetails{}

	keys := reflect.ValueOf(packages).MapKeys()
	keysOrder := func(i, j int) bool { return keys[i].Interface().(string) < keys[j].Interface().(string) }
	sort.Slice(keys, keysOrder)

	for _, key := range keys {
		namePath := key.Interface().(string)
		detail := packages[namePath]
		if namePath == "" {
			continue
		}

		finalName := detail.Name
		if finalName == "" {
			finalName = extractNpmPackageName(namePath)
		}

		finalVersion := detail.Version

		commit := tryExtractCommit(detail.Resolved)

		// if there is a commit, we want to deduplicate based on that rather than
		// the version (the versions must match anyway for the commits to match)
		if commit != "" {
			finalVersion = commit
		}

		if finalVersion == "" {
			// If version and commit are not set in the lockfile, it means the package is defined locally
			// with its own package.json, without any version defined for it, lets default on 0.0.0
			detail.Version = "0.0.0"
		}

		_, exists := details[finalName+"@"+finalVersion]
		if !exists && !detail.Link {
			details[finalName+"@"+finalVersion] = PackageDetails{
				Name:      finalName,
				Version:   detail.Version,
				Ecosystem: NpmEcosystem,
				CompareAs: NpmEcosystem,
				BlockLocation: models.FilePosition{
					Line:     detail.Line,
					Column:   detail.Column,
					Filename: path,
				},
				Commit:    commit,
				DepGroups: detail.depGroups(),
			}
		}
	}

	return details
}

func parseNpmLock(lockfile NpmLockfile, lines []string) map[string]PackageDetails {
	if lockfile.Packages != nil {
		fileposition.InJSON("packages", lockfile.Packages, lines, 0)

		return parseNpmLockPackages(lockfile.Packages, lockfile.SourceFile)
	}

	fileposition.InJSON("dependencies", lockfile.Dependencies, lines, 0)

	return parseNpmLockDependencies(lockfile.Dependencies, lockfile.SourceFile)
}

type NpmLockExtractor struct{}

func (e NpmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "package-lock.json"
}

func (e NpmLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *NpmLockfile

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
	parsedLockfile.SourceFile = f.Path()

	return pkgDetailsMapToSlice(parseNpmLock(*parsedLockfile, lines)), nil
}

var _ Extractor = NpmLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("package-lock.json", NpmLockExtractor{})
}

func ParseNpmLock(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, NpmLockExtractor{})
}
