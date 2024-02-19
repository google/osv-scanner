package util

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

var OSVEcosystem = map[resolve.System]models.Ecosystem{
	resolve.NPM:   models.EcosystemNPM,
	resolve.Maven: models.EcosystemMaven,
}

func VKToPackageDetails(vk resolve.VersionKey) lockfile.PackageDetails {
	return lockfile.PackageDetails{
		Name:      vk.Name,
		Version:   vk.Version,
		Ecosystem: lockfile.Ecosystem(OSVEcosystem[vk.System]),
		CompareAs: lockfile.Ecosystem(OSVEcosystem[vk.System]),
	}
}
