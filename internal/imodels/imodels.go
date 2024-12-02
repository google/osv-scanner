package imodels

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

// TODO: This will be removed and replaced with the V2 model
type ScannedPackage struct {
	PURL        string
	Name        string
	Ecosystem   lockfile.Ecosystem
	Commit      string
	Version     string
	Source      models.SourceInfo
	ImageOrigin *models.ImageOriginDetails
	DepGroups   []string
}
