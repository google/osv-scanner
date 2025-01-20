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

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/google/osv-scanner/internal/utility/fileposition"

	"github.com/google/osv-scanner/pkg/models"
)

type NpmLockDependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version      string                        `json:"version"`
	Dependencies map[string]*NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires map[string]string `json:"requires,omitempty"`

	models.FilePosition
}

func (dep *NpmLockDependency) GetNestedDependencies() map[string]*models.FilePosition {
	result := make(map[string]*models.FilePosition)
	for key, value := range dep.Dependencies {
		result[key] = &value.FilePosition
	}

	return result
}

type NpmLockPackage struct {
	// For an aliased package, Name is the real package name
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`

	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`

	Dev         bool `json:"dev,omitempty"`
	DevOptional bool `json:"devOptional,omitempty"`
	Optional    bool `json:"optional,omitempty"`

	Link bool `json:"link,omitempty"`

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

type npmPackageDetailsMap map[string]PackageDetails

// mergeNpmDepsGroups handles merging the dependency groups of packages within the
// NPM ecosystem, since they can appear multiple times in the same dependency tree
//
// the merge happens almost as you'd expect, except that if either given packages
// belong to no groups, then that is the result since it indicates the package
// is implicitly a production dependency.
func mergeNpmDepsGroups(a, b PackageDetails) []string {
	// if either group includes no groups, then the package is in the "production" group
	if len(a.DepGroups) == 0 || len(b.DepGroups) == 0 {
		return nil
	}

	combined := make([]string, 0, len(a.DepGroups)+len(b.DepGroups))
	combined = append(combined, a.DepGroups...)
	combined = append(combined, b.DepGroups...)

	slices.Sort(combined)

	return slices.Compact(combined)
}

func (pdm npmPackageDetailsMap) add(key string, details PackageDetails) {
	existing, ok := pdm[key]

	if ok {
		details.DepGroups = mergeNpmDepsGroups(existing, details)
	}

	pdm[key] = details
}

func (dep *NpmLockDependency) depGroups() []string {
	groups := make([]string, 0)
	if dep.Optional {
		groups = append(groups, "optional")
	}
	if dep.Dev {
		groups = append(groups, "dev")
	} else {
		groups = append(groups, "prod")
	}

	return groups
}

func parseNpmLockDependencies(dependencies map[string]*NpmLockDependency) map[string]PackageDetails {
	details := npmPackageDetailsMap{}

	keys := reflect.ValueOf(dependencies).MapKeys()
	keysOrder := func(i, j int) bool { return keys[i].Interface().(string) < keys[j].Interface().(string) }
	sort.Slice(keys, keysOrder)

	for _, key := range keys {
		name := key.Interface().(string)
		detail := dependencies[name]
		if detail.Dependencies != nil {
			nestedDeps := parseNpmLockDependencies(detail.Dependencies)
			for k, v := range nestedDeps {
				details.add(k, v)
			}
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
			finalVersion = ""
			version = ""
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

		details.add(name+"@"+version, PackageDetails{
			Name:           name,
			Version:        finalVersion,
			PackageManager: models.NPM,
			Ecosystem:      NpmEcosystem,
			CompareAs:      NpmEcosystem,
			Commit:         commit,
			DepGroups:      detail.depGroups(),
		})
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

func extractRootKeyPackageName(name string) string {
	_, right, _ := strings.Cut(name, "/")
	return right
}

func (pkg NpmLockPackage) depGroups() []string {
	groups := make([]string, 0)
	if pkg.Dev {
		groups = append(groups, "dev")
	}
	if pkg.Optional {
		groups = append(groups, "optional")
	}
	if pkg.DevOptional {
		groups = append(groups, "dev", "optional")
	}
	if !pkg.Dev && !pkg.DevOptional {
		groups = append(groups, "prod")
	}

	return groups
}

func parseNpmLockPackages(packages map[string]*NpmLockPackage) map[string]PackageDetails {
	details := npmPackageDetailsMap{}

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

		// Element "" in packages, contains in its dependencies/devDependencies
		// the dependencies with the version written as it appears in the package.json
		var targetVersions []string
		var targetVersion string
		rootKey := extractRootKeyPackageName(namePath)
		if p, ok := packages[""]; ok {
			if dep, ok := p.Dependencies[rootKey]; ok {
				targetVersion = dep
			} else if devDep, ok := p.DevDependencies[rootKey]; ok {
				targetVersion = devDep
			}
		}

		if len(targetVersion) > 0 {
			// Clean aliased target version
			if strings.HasPrefix(targetVersion, "npm:") {
				_, targetVersion, _ = strings.Cut(targetVersion, "@")
			}

			// Clean some prefixes that may not be included in package.json
			prefixes := []string{"file", "link", "portal"}
			for _, prefix := range prefixes {
				if strings.HasPrefix(targetVersion, prefix+":") {
					targetVersion = strings.TrimPrefix(targetVersion, prefix+":")
					targetVersion = strings.TrimPrefix(targetVersion, "./")
				}
			}

			targetVersions = []string{targetVersion}
		}

		if !detail.Link {
			details.add(finalName+"@"+finalVersion, PackageDetails{
				Name:           finalName,
				Version:        detail.Version,
				TargetVersions: targetVersions,
				PackageManager: models.NPM,
				Ecosystem:      NpmEcosystem,
				CompareAs:      NpmEcosystem,
				Commit:         commit,
				DepGroups:      detail.depGroups(),
			})
		}
	}

	return details
}

func parseNpmLock(lockfile NpmLockfile, lines []string) map[string]PackageDetails {
	if lockfile.Packages != nil {
		fileposition.InJSON("packages", lockfile.Packages, lines, 0)

		return parseNpmLockPackages(lockfile.Packages)
	}

	fileposition.InJSON("dependencies", lockfile.Dependencies, lines, 0)

	return parseNpmLockDependencies(lockfile.Dependencies)
}

type NpmLockExtractor struct {
	WithMatcher
}

func (e NpmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "package-lock.json"
}

func (e NpmLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *NpmLockfile

	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}
	contentString := string(contentBytes)
	lines := strings.Split(contentString, "\n")
	decoder := json.NewDecoder(strings.NewReader(contentString))

	if err := decoder.Decode(&parsedLockfile); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	parsedLockfile.SourceFile = f.Path()

	return maps.Values(parseNpmLock(*parsedLockfile, lines)), nil
}

var NpmExtractor = NpmLockExtractor{
	WithMatcher{Matcher: PackageJSONMatcher{}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("package-lock.json", NpmExtractor)
}

func ParseNpmLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, NpmExtractor)
}
