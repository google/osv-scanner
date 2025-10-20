// Package clientinterfaces defines interfaces for external accessors used in osv-scanner.
package clientinterfaces

import (
	"context"

	"github.com/google/osv-scanner/v2/internal/imodels"
)

type LicenseMatcher interface {
	MatchLicenses(ctx context.Context, psr []imodels.PackageScanResult) error
}
