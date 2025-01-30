package osvscannerjson

import "github.com/google/osv-scanner/v2/pkg/models"

// Metadata holds the metadata for osvscanner.json
type Metadata struct {
	Ecosystem  string
	SourceInfo models.SourceInfo
}
