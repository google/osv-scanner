package osvscanner

import (
	"github.com/google/osv-scanner/pkg/models"
)

// PURLToPackage converts a Package URL string to models.PackageInfo
//
// Deprecated: Use the PURLToPackage in the models package instead.
func PURLToPackage(purl string) (models.PackageInfo, error) {
	return models.PURLToPackage(purl)
}
