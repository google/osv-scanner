// Package util provides utility functions for dependency resolution.
package util

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// OSVEcosystem maps resolve.System constants to osvschema.Ecosystem constants
//
// TODO: use osvschema.Ecosystem or imodel's osvecosystem.Parsed
var OSVEcosystem = map[resolve.System]osvschema.Ecosystem{
	resolve.NPM:   osvschema.EcosystemNPM,
	resolve.Maven: osvschema.EcosystemMaven,
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
