// Package depsdev contains constants and mappings for the deps.dev API.
package depsdev

import (
	"github.com/ossf/osv-schema/bindings/go/osvconstants"

	depsdevpb "deps.dev/api/v3"
)

// DepsdevAPI is the URL to the deps.dev API. It is documented at
// docs.deps.dev/api.
const DepsdevAPI = "api.deps.dev:443"

// System maps from a lockfile system to the depsdev API system.
var System = map[osvconstants.Ecosystem]depsdevpb.System{
	osvconstants.EcosystemNPM:      depsdevpb.System_NPM,
	osvconstants.EcosystemNuGet:    depsdevpb.System_NUGET,
	osvconstants.EcosystemCratesIO: depsdevpb.System_CARGO,
	osvconstants.EcosystemGo:       depsdevpb.System_GO,
	osvconstants.EcosystemMaven:    depsdevpb.System_MAVEN,
	osvconstants.EcosystemPyPI:     depsdevpb.System_PYPI,
}
