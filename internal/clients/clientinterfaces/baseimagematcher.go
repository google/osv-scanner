// Package clientinterfaces defines interfaces for external accessors used in osv-scanner.
package clientinterfaces

import (
	"context"

	"github.com/google/osv-scanner/v2/pkg/models"
)

type BaseImageMatcher interface {
	MatchBaseImages(ctx context.Context, layerMetadata []models.LayerMetadata) ([][]models.BaseImageDetails, error)
}
