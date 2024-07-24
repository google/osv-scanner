package lockfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
)

type NuGetLockPackage struct {
	Resolved string `json:"resolved"`
}

// NuGetLockfile contains the required dependency information as defined in
// https://github.com/NuGet/NuGet.Client/blob/6.5.0.136/src/NuGet.Core/NuGet.ProjectModel/ProjectLockFile/PackagesLockFileFormat.cs
type NuGetLockfile struct {
	Version      int                                    `json:"version"`
	Dependencies map[string]map[string]NuGetLockPackage `json:"dependencies"`
}

const NuGetEcosystem Ecosystem = "NuGet"

func parseNuGetLockDependencies(dependencies map[string]NuGetLockPackage) map[string]*Inventory {
	details := map[string]*Inventory{}

	for name, dependency := range dependencies {
		details[name+"@"+dependency.Resolved] = &Inventory{
			Name:    name,
			Version: dependency.Resolved,
		}
	}

	return details
}

func parseNuGetLock(lockfile NuGetLockfile) ([]*Inventory, error) {
	details := map[string]*Inventory{}

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks
	for _, dependencies := range lockfile.Dependencies {
		for name, detail := range parseNuGetLockDependencies(dependencies) {
			details[name] = detail
		}
	}

	return maps.Values(details), nil
}

type NuGetLockExtractor struct{}

// Name of the extractor
func (e NuGetLockExtractor) Name() string { return "dotnet/nugetpackagelock" }

// Version of the extractor
func (e NuGetLockExtractor) Version() int { return 0 }

func (e NuGetLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e NuGetLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "packages.lock.json"
}

func (e NuGetLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *NuGetLockfile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	if parsedLockfile.Version != 1 && parsedLockfile.Version != 2 {
		return []*Inventory{}, fmt.Errorf("could not extract: unsupported lock file version %d", parsedLockfile.Version)
	}

	out, err := parseNuGetLock(*parsedLockfile)
	if err != nil {
		return []*Inventory{}, err
	}

	for i := range out {
		out[i].Locations = []string{input.Path}
	}

	return out, nil
}

var _ Extractor = NuGetLockExtractor{}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e NuGetLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeNuget,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e NuGetLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e NuGetLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case NuGetLockExtractor:
		return string(NuGetEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}
