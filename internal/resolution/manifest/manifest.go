package manifest

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scanner/pkg/lockfile"
)

type Manifest struct {
	FilePath          string                       // Path to the manifest file on disk
	Root              resolve.Version              // Version representing this package
	Requirements      []resolve.RequirementVersion // All direct requirements, including dev
	Groups            map[RequirementKey][]string  // Dependency groups that the imports belong to
	LocalManifests    []Manifest                   // manifests of local packages
	EcosystemSpecific any                          // Any ecosystem-specific information needed
}

func newManifest() Manifest {
	return Manifest{
		Groups: make(map[RequirementKey][]string),
	}
}

func (m Manifest) System() resolve.System {
	return m.Root.System
}

func (m Manifest) Clone() Manifest {
	return Manifest{
		FilePath:          m.FilePath,
		Root:              m.Root,
		Requirements:      slices.Clone(m.Requirements),
		Groups:            maps.Clone(m.Groups),
		LocalManifests:    slices.Clone(m.LocalManifests),
		EcosystemSpecific: m.EcosystemSpecific, // TODO: Deep copy this?
	}
}

type DependencyPatch struct {
	Pkg          resolve.PackageKey // The package this applies to
	Type         dep.Type           // The dependency type
	OrigRequire  string             // The original requirement string e.g. "1.*.*"
	NewRequire   string             // The new requirement string e.g. "2.*.*"
	OrigResolved string             // The version the original resolves to e.g. "1.2.3" (for display only)
	NewResolved  string             // The version the new resolves to e.g. "2.4.6" (for display only)
}

type Patch struct {
	Manifest          *Manifest         // The original manifest
	Deps              []DependencyPatch // Changed direct dependencies
	EcosystemSpecific any               // Any ecosystem-specific information
}

type ReadWriter interface {
	// System returns which ecosystem this ReadWriter is for.
	System() resolve.System
	// Read parses a manifest file into a Manifest, possibly recursively following references to other local manifest files
	Read(file lockfile.DepFile) (Manifest, error)
	// Write applies the Patch to the manifest, with minimal changes to the file.
	// `original` is the original manifest file to read from. The updated manifest is written to `output`.
	Write(original lockfile.DepFile, output io.Writer, patches Patch) error
}

// Overwrite applies the ManifestPatch to the manifest at filename.
// Used so as to not have the same file open for reading and writing at the same time.
func Overwrite(rw ReadWriter, filename string, p Patch) error {
	r, err := lockfile.OpenLocalDepFile(filename)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = rw.Write(r, &buf, p)
	r.Close() // Make sure the file is closed before we start writing to it.
	if err != nil {
		return err
	}

	//nolint:gosec // Complaining about the 0644 permissions.
	// The file already exists anyway so the permissions don't matter.
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

func GetReadWriter(pathToManifest string, registry string) (ReadWriter, error) {
	base := filepath.Base(pathToManifest)
	switch {
	case base == "pom.xml":
		return NewMavenReadWriter(registry)
	case base == "package.json":
		return NpmReadWriter{}, nil
	default:
		return nil, fmt.Errorf("unsupported manifest type: %s", base)
	}
}

// A RequirementKey is a comparable type that uniquely identifies a package dependency in a manifest.
// It does not include the version specification.
type RequirementKey struct {
	resolve.PackageKey
	EcosystemSpecific any
}

func MakeRequirementKey(requirement resolve.RequirementVersion) RequirementKey {
	switch requirement.System {
	case resolve.NPM:
		return npmRequirementKey(requirement)
	case resolve.Maven:
		return mavenRequirementKey(requirement)
	case resolve.UnknownSystem:
		fallthrough
	default:
		return RequirementKey{PackageKey: requirement.PackageKey}
	}
}
