package filesystem

import (
	"context"
	"io"
	"io/fs"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
)

// ScanInput represents a filesystem path to a readable file where inventory can be extracted.
type ScanInput struct {
	// FS for file access. This is rooted at /.
	FS plugin.FS
	// Input path, relative to the root directory.
	Path string
	// The root directory to start all extractions from.
	ScanRoot string
	// A reader for accessing contents of the "main" file.
	// Note that the file is closed by the core library, not the plugin.
	Reader io.Reader
	Info   fs.FileInfo
}

// Extractor is the filesystem-based inventory extraction plugin, used to extract inventory data
// from the filesystem such as OS and language packages.
type Extractor interface {
	extractor.Extractor
	// FileRequired should return true if the file described by path and file info is
	// relevant for the extractor.
	// Note that the plugin doesn't traverse the filesystem itself but relies on the core
	// library for that.
	FileRequired(path string, fileinfo fs.FileInfo) bool
	// Extract extracts inventory data relevant for the extractor from a given file.
	Extract(ctx context.Context, input *ScanInput) ([]*extractor.Inventory, error)
}
