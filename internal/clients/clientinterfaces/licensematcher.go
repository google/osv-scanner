package clientinterfaces

import (
	"context"

	"github.com/google/osv-scanner/internal/imodels"
)

type LicenseMatcher interface {
	MatchLicenses(ctx context.Context, psr []imodels.PackageScanResult) error
}
