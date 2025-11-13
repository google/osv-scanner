// Package util provides utility functions for dependency resolution.
package util

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

// OSVEcosystem maps resolve.System constants to osvschema.Ecosystem constants
//
// TODO: use osvschema.Ecosystem or imodel's osvecosystem.Parsed
var OSVEcosystem = map[resolve.System]osvconstants.Ecosystem{
	resolve.NPM:   osvconstants.EcosystemNPM,
	resolve.Maven: osvconstants.EcosystemMaven,
}

var PURLType = map[resolve.System]string{
	resolve.NPM:   purl.TypeNPM,
	resolve.Maven: purl.TypeMaven,
}

func VKToPackageInfo(vk resolve.VersionKey) imodels.PackageInfo {
	return imodels.FromInventory(
		&extractor.Package{
			Name:     vk.Name,
			Version:  vk.Version,
			PURLType: PURLType[vk.System],
		},
	)
}
