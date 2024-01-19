package manifest

import (
	"maps"
	"slices"

	"deps.dev/util/resolve"
)

type Manifest struct {
	FilePath          string                          // Path to the manifest file on disk
	Root              resolve.Version                 // Version representing this package
	Requirements      []resolve.RequirementVersion    // All direct requirements, including dev
	Groups            map[resolve.PackageKey][]string // Dependency groups that the imports belong to
	LocalManifests    []Manifest                      // manifests of local packages
	EcosystemSpecific any                             // Any ecosystem-specific information needed
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
