package lockfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type NpmLockDependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version      string                       `json:"version"`
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires map[string]string `json:"requires,omitempty"`
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
}

type NpmLockfile struct {
	Version int `json:"lockfileVersion"`
	// npm v1- lockfiles use "dependencies"
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`
	// npm v2+ lockfiles use "packages"
	Packages map[string]NpmLockPackage `json:"packages,omitempty"`
}

const NpmEcosystem Ecosystem = "npm"

type npmInventoryMap map[string]*Inventory

// mergeNpmDepsGroups handles merging the dependency groups of packages within the
// NPM ecosystem, since they can appear multiple times in the same dependency tree
//
// the merge happens almost as you'd expect, except that if either given packages
// belong to no groups, then that is the result since it indicates the package
// is implicitly a production dependency.
func mergeNpmDepsGroups(a, b *Inventory) []string {
	aDepGroups := a.Metadata.(DepGroups).DepGroups()
	bDepGroups := b.Metadata.(DepGroups).DepGroups()
	// if either group includes no groups, then the package is in the "production" group
	if len(aDepGroups) == 0 || len(bDepGroups) == 0 {
		return nil
	}

	combined := make([]string, 0, len(aDepGroups)+len(bDepGroups))
	combined = append(combined, aDepGroups...)
	combined = append(combined, bDepGroups...)

	slices.Sort(combined)

	return slices.Compact(combined)
}

func (pdm npmInventoryMap) add(key string, details *Inventory) {
	existing, ok := pdm[key]

	if ok {
		details.Metadata.(*DepGroupMetadata).depGroups = mergeNpmDepsGroups(existing, details)
	}

	pdm[key] = details
}

func (dep NpmLockDependency) depGroups() []string {
	if dep.Dev && dep.Optional {
		return []string{"dev", "optional"}
	}
	if dep.Dev {
		return []string{"dev"}
	}
	if dep.Optional {
		return []string{"optional"}
	}

	return nil
}

func parseNpmLockDependencies(dependencies map[string]NpmLockDependency) map[string]*Inventory {
	details := npmInventoryMap{}

	for name, detail := range dependencies {
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

		details.add(name+"@"+version, &Inventory{
			Name:    name,
			Version: finalVersion,
			SourceCode: &SourceCodeIdentifier{
				Commit: commit,
			},
			Metadata: &DepGroupMetadata{
				depGroups: detail.depGroups(),
			},
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

func (pkg NpmLockPackage) depGroups() []string {
	if pkg.Dev {
		return []string{"dev"}
	}
	if pkg.Optional {
		return []string{"optional"}
	}
	if pkg.DevOptional {
		return []string{"dev", "optional"}
	}

	return nil
}

func parseNpmLockPackages(packages map[string]NpmLockPackage) map[string]*Inventory {
	details := npmInventoryMap{}

	for namePath, detail := range packages {
		if namePath == "" {
			continue
		}

		finalName := detail.Name
		if finalName == "" {
			finalName = extractNpmPackageName(namePath)
		}

		finalVersion := detail.Version
		// TODO: This should try to extract the source repository as well
		commit := tryExtractCommit(detail.Resolved)

		// if there is a commit, we want to deduplicate based on that rather than
		// the version (the versions must match anyway for the commits to match)
		if commit != "" {
			finalVersion = commit
		}

		details.add(finalName+"@"+finalVersion, &Inventory{
			Name:    finalName,
			Version: detail.Version,
			SourceCode: &SourceCodeIdentifier{
				Commit: commit,
			},
			Metadata: &DepGroupMetadata{
				depGroups: detail.depGroups(),
			},
		})
	}

	return details
}

func parseNpmLock(lockfile NpmLockfile) map[string]*Inventory {
	if lockfile.Packages != nil {
		return parseNpmLockPackages(lockfile.Packages)
	}

	return parseNpmLockDependencies(lockfile.Dependencies)
}

type NpmLockExtractor struct{}

// Name of the extractor
func (e NpmLockExtractor) Name() string { return "javascript/packagelockjson" }

// Version of the extractor
func (e NpmLockExtractor) Version() int { return 0 }

func (e NpmLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e NpmLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "package-lock.json"
}

func (e NpmLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *NpmLockfile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	return maps.Values(parseNpmLock(*parsedLockfile)), nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e NpmLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeCargo,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e NpmLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e NpmLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case NpmLockExtractor:
		return string(NpmEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = NpmLockExtractor{}
