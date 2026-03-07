// Package clientinterfaces defines interfaces for external accessors used in osv-scanner.
package clientinterfaces

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
)

type LicenseMatcher interface {
	MatchLicenses(ctx context.Context, psr []*extractor.Package) error
}
