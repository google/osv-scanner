// Package conanlock extracts conan.lock files.
package conanlock

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

type conanReference struct {
	Name            string
	Version         string
	Username        string
	Channel         string
	RecipeRevision  string
	PackageID       string
	PackageRevision string
	TimeStamp       string
}

type conanGraphNode struct {
	Pref      string `json:"pref"`
	Ref       string `json:"ref"`
	Options   string `json:"options"`
	PackageID string `json:"package_id"`
	Prev      string `json:"prev"`
	Path      string `json:"path"`
	Context   string `json:"context"`
}

type conanGraphLock struct {
	Nodes map[string]conanGraphNode `json:"nodes"`
}

type conanLockFile struct {
	Version string `json:"version"`
	// conan v0.4- lockfiles use "graph_lock", "profile_host" and "profile_build"
	GraphLock    conanGraphLock `json:"graph_lock,omitempty"`
	ProfileHost  string         `json:"profile_host,omitempty"`
	ProfileBuild string         `json:"profile_build,omitempty"`
	// conan v0.5+ lockfiles use "requires", "build_requires" and "python_requires"
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
}

// TODO this is tentative and subject to change depending on the OSV schema
const conanEcosystem string = "ConanCenter"

func parseConanRenference(ref string) conanReference {
	// very flexible format name/version[@username[/channel]][#rrev][:pkgid[#prev]][%timestamp]
	var reference conanReference

	parts := strings.SplitN(ref, "%", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.TimeStamp = parts[1]
	}

	parts = strings.SplitN(ref, ":", 2)
	if len(parts) == 2 {
		ref = parts[0]
		parts = strings.SplitN(parts[1], "#", 2)
		reference.PackageID = parts[0]
		if len(parts) == 2 {
			reference.PackageRevision = parts[1]
		}
	}

	parts = strings.SplitN(ref, "#", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.RecipeRevision = parts[1]
	}

	parts = strings.SplitN(ref, "@", 2)
	if len(parts) == 2 {
		ref = parts[0]
		UsernameChannel := parts[1]

		parts = strings.SplitN(UsernameChannel, "/", 2)
		reference.Username = parts[0]
		if len(parts) == 2 {
			reference.Channel = parts[1]
		}
	}

	parts = strings.SplitN(ref, "/", 2)
	if len(parts) == 2 {
		reference.Name = parts[0]
		reference.Version = parts[1]
	} else {
		// consumer conanfile.txt or conanfile.py might not have a name
		reference.Name = ""
		reference.Version = ref
	}

	return reference
}

func parseConanV1Lock(lockfile conanLockFile) []*extractor.Inventory {
	var reference conanReference
	packages := make([]*extractor.Inventory, 0, len(lockfile.GraphLock.Nodes))

	for _, node := range lockfile.GraphLock.Nodes {
		if node.Path != "" {
			// a local "conanfile.txt", skip
			continue
		}

		if node.Pref != "" {
			// old format 0.3 (conan 1.27-) lockfiles use "pref" instead of "ref"
			reference = parseConanRenference(node.Pref)
		} else if node.Ref != "" {
			reference = parseConanRenference(node.Ref)
		} else {
			continue
		}
		// skip entries with no name, they are most likely consumer's conanfiles
		// and not dependencies to be searched in a database anyway
		if reference.Name == "" {
			continue
		}
		packages = append(packages, &extractor.Inventory{
			Name:    reference.Name,
			Version: reference.Version,
			Metadata: othermetadata.DepGroupMetadata{
				DepGroupVals: []string{},
			},
		})
	}

	return packages
}

func parseConanRequires(packages *[]*extractor.Inventory, requires []string, group string) {
	for _, ref := range requires {
		reference := parseConanRenference(ref)
		// skip entries with no name, they are most likely consumer's conanfiles
		// and not dependencies to be searched in a database anyway
		if reference.Name == "" {
			continue
		}

		*packages = append(*packages, &extractor.Inventory{
			Name:    reference.Name,
			Version: reference.Version,
			Metadata: othermetadata.DepGroupMetadata{
				DepGroupVals: []string{group},
			},
		})
	}
}

func parseConanV2Lock(lockfile conanLockFile) []*extractor.Inventory {
	packages := make(
		[]*extractor.Inventory,
		0,
		uint64(len(lockfile.Requires))+uint64(len(lockfile.BuildRequires))+uint64(len(lockfile.PythonRequires)),
	)

	parseConanRequires(&packages, lockfile.Requires, "requires")
	parseConanRequires(&packages, lockfile.BuildRequires, "build-requires")
	parseConanRequires(&packages, lockfile.PythonRequires, "python-requires")

	return packages
}

func parseConanLock(lockfile conanLockFile) []*extractor.Inventory {
	if lockfile.GraphLock.Nodes != nil {
		return parseConanV1Lock(lockfile)
	}

	return parseConanV2Lock(lockfile)
}

// Extractor extracts Conan packages from conan.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "cpp/conanlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Conan lockfile patterns.
func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "conan.lock"
}

// Extract extracts packages from conan.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *conanLockFile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)
	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	inv := parseConanLock(*parsedLockfile)

	for i := range inv {
		inv[i].Locations = []string{input.Path}
	}

	return inv, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeConan,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

// Ecosystem returns the OSV ecosystem ('ConanCenter') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return conanEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
