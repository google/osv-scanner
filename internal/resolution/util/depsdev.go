package util

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// TODO: use osvschema.Ecosystem or imodel's ecosystem.Parsed
var OSVEcosystem = map[resolve.System]osvschema.Ecosystem{
	resolve.NPM:   osvschema.EcosystemNPM,
	resolve.Maven: osvschema.EcosystemMaven,
}

func VKToPackageInfo(vk resolve.VersionKey) imodels.PackageInfo {
	return imodels.FromInventory(
		&extractor.Package{
			Name:    vk.Name,
			Version: vk.Version,
			Extractor: ecosystemmock.Extractor{
				MockEcosystem: string(OSVEcosystem[vk.System]),
			},
		},
	)
}
