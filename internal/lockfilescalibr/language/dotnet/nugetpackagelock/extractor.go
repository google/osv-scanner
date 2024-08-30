package nugetpackagelock

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
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

const NuGetEcosystem string = "NuGet"

func parseNuGetLockDependencies(dependencies map[string]NuGetLockPackage) map[string]*extractor.Inventory {
	details := map[string]*extractor.Inventory{}

	for name, dependency := range dependencies {
		details[name+"@"+dependency.Resolved] = &extractor.Inventory{
			Name:    name,
			Version: dependency.Resolved,
		}
	}

	return details
}

func parseNuGetLock(lockfile NuGetLockfile) []*extractor.Inventory {
	details := map[string]*extractor.Inventory{}

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks
	for _, dependencies := range lockfile.Dependencies {
		for name, detail := range parseNuGetLockDependencies(dependencies) {
			details[name] = detail
		}
	}

	return maps.Values(details)
}

type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "dotnet/nugetpackagelock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "packages.lock.json"
}

func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *NuGetLockfile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	if parsedLockfile.Version != 1 && parsedLockfile.Version != 2 {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract: unsupported lock file version %d", parsedLockfile.Version)
	}

	out := parseNuGetLock(*parsedLockfile)

	for i := range out {
		out[i].Locations = []string{input.Path}
	}

	return out, nil
}

var _ filesystem.Extractor = Extractor{}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeNuget,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return NuGetEcosystem, nil
}
