package lockfilescalibr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

type ConanReference struct {
	Name            string
	Version         string
	Username        string
	Channel         string
	RecipeRevision  string
	PackageID       string
	PackageRevision string
	TimeStamp       string
}

type ConanGraphNode struct {
	Pref      string `json:"pref"`
	Ref       string `json:"ref"`
	Options   string `json:"options"`
	PackageID string `json:"package_id"`
	Prev      string `json:"prev"`
	Path      string `json:"path"`
	Context   string `json:"context"`
}

type ConanGraphLock struct {
	Nodes map[string]ConanGraphNode `json:"nodes"`
}

type ConanLockFile struct {
	Version string `json:"version"`
	// conan v0.4- lockfiles use "graph_lock", "profile_host" and "profile_build"
	GraphLock    ConanGraphLock `json:"graph_lock,omitempty"`
	ProfileHost  string         `json:"profile_host,omitempty"`
	ProfileBuild string         `json:"profile_build,omitempty"`
	// conan v0.5+ lockfiles use "requires", "build_requires" and "python_requires"
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
}

// TODO this is tentative and subject to change depending on the OSV schema
const ConanEcosystem Ecosystem = "ConanCenter"

func parseConanRenference(ref string) ConanReference {
	// very flexible format name/version[@username[/channel]][#rrev][:pkgid[#prev]][%timestamp]
	var reference ConanReference

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

func parseConanV1Lock(lockfile ConanLockFile) []*extractor.Inventory {
	var reference ConanReference
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
			Metadata: DepGroupMetadata{
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
			Metadata: DepGroupMetadata{
				DepGroupVals: []string{group},
			},
		})
	}
}

func parseConanV2Lock(lockfile ConanLockFile) []*extractor.Inventory {
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

func parseConanLock(lockfile ConanLockFile) []*extractor.Inventory {
	if lockfile.GraphLock.Nodes != nil {
		return parseConanV1Lock(lockfile)
	}

	return parseConanV2Lock(lockfile)
}

type ConanLockExtractor struct{}

// Name of the extractor
func (e ConanLockExtractor) Name() string { return "cpp/conanlock" }

// Version of the extractor
func (e ConanLockExtractor) Version() int { return 0 }

func (e ConanLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e ConanLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "conan.lock"
}

func (e ConanLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *ConanLockFile

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
func (e ConanLockExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeConan,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e ConanLockExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e ConanLockExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case ConanLockExtractor:
		return string(ConanEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = ConanLockExtractor{}
