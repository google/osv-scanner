package util

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/pkg/models"
)

var OSVEcosystem = map[resolve.System]models.Ecosystem{
	resolve.NPM:   models.EcosystemNPM,
	resolve.Maven: models.EcosystemMaven,
}
