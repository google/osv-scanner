// Package depsdev contains constants and mappings for the deps.dev API.
package depsdev

import (
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	depsdevpb "deps.dev/api/v3"
)

// DepsdevAPI is the URL to the deps.dev API. It is documented at
// docs.deps.dev/api.
const DepsdevAPI = "api.deps.dev:443"

// System maps from a lockfile system to the depsdev API system.
var System = map[osvschema.Ecosystem]depsdevpb.System{
	osvschema.EcosystemNPM:      depsdevpb.System_NPM,
	osvschema.EcosystemNuGet:    depsdevpb.System_NUGET,
	osvschema.EcosystemCratesIO: depsdevpb.System_CARGO,
	osvschema.EcosystemGo:       depsdevpb.System_GO,
	osvschema.EcosystemMaven:    depsdevpb.System_MAVEN,
	osvschema.EcosystemPyPI:     depsdevpb.System_PYPI,
}
