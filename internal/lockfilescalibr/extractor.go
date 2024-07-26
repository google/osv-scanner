package lockfilescalibr

import (
	"context"
	"errors"
	"io"
	"io/fs"

	"github.com/package-url/packageurl-go"
)

// ---
// Updated extractors and notes:
//
// - Moved to tabular tests
// - Kept PackageDetails for some packages and added a simple conversion function
//   to inventory before returning
// - Updated tests to test Inventory output
// - Updated interfaces to follow the new interface
// - Copied the interface into this file. This is temporary until the move into osv-scalibr, which will contain both
// - All ToPURL functions need to be looked at to see they are suitable
// - We need to add tests for ToPurl() and Ecosystem() functions
// - Because scalibr uses a virtual FS to walk over files, all paths are absolute, but will not start with /
// ---

var ErrNotImplemented = errors.New("not implemented")
var ErrWrongExtractor = errors.New("this extractor did not create this inventory")

type Annotation int

// Plugin is the part of the plugin interface that's shared between extractors and detectors.
type Plugin interface {
	// A unique name used to identify this plugin.
	Name() string
	// Plugin version, should get bumped whenever major changes are made.
	Version() int
}

// FS is a filesystem interface that allows the opening of files, reading of
// directories, and performing stat on files.
//
// FS implementations may return ErrNotImplemented for `Open`, `ReadDir` and `Stat`.
// Extractor implementations must decide whether the error is fatal or can be ignored.
//
// fs.FS implementations MUST implement io.ReaderAt for opened files to enable random access.
type FS interface {
	fs.FS
	fs.ReadDirFS
	fs.StatFS
}

// ScanInput represents a filesystem path to a readable file where inventory can be extracted.
type ScanInput struct {
	// FS for file access. This is rooted at /.
	FS FS
	// Input path, relative to the root directory.
	Path string
	// The root directory to start all extractions from.
	ScanRoot string
	// A reader for accessing contents of the "main" file.
	// Note that the file is closed by the core library, not the plugin.
	Reader io.Reader
	Info   fs.FileInfo
}

type Requirements struct {
	// Whether this extractor requires network access.
	Network bool

	// Whether this extractor requires a real filesystem. If true, extractors
	// may access the ScanInput file paths directly, bypassing the fs.FS.
	RealFS bool
}

type SourceCodeIdentifier struct {
	Repo   string
	Commit string
}

type Extractor interface {
	Plugin

	// PathRequired should return true if the input is
	// relevant for the extractor. This should be used as a lightweight filtering step.
	FileRequired(path string, fileInfo fs.FileInfo) bool
	// Extract extracts inventory data relevant for the extractor from a given input.
	Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error)

	// Requirements returns the set of operating requirements that the extractor
	// requires.
	Requirements() Requirements

	// ToPURL converts an inventory created by this extractor into a PURL.
	ToPURL(i *Inventory) (*packageurl.PackageURL, error)
	// ToCPEs converts an inventory created by this extractor into CPEs, if supported.
	ToCPEs(i *Inventory) ([]string, error)
	// Ecosystem returns the Ecosystem of the given inventory created by this
	// extractor.
	Ecosystem(i *Inventory) (string, error)
}

type DepGroups interface {
	DepGroups() []string
}

type Inventory struct {
	// Source code-level identifier.
	SourceCode *SourceCodeIdentifier
	Name       string
	// The version of this package. The version follows the versioning scheme for specified Ecosystem.
	Version string
	// The paths of the files from which the information about the inventory is extracted
	Locations []string
	// The Extractor that found this software instance. Set by the core library.
	Extractor Extractor
	// The additional data found in the package, specific to the extractor.
	Metadata    any
	Annotations []Annotation // See go/scalibr-annotations for details.
}

func (i Inventory) Ecosystem() (string, error) {
	return i.Extractor.Ecosystem(&i)
}

// DepGroupMetadata is a metadata struct that only supports DepGroups
type DepGroupMetadata struct {
	DepGroupVals []string
}

var _ DepGroups = DepGroupMetadata{}

func (dgm DepGroupMetadata) DepGroups() []string {
	return dgm.DepGroupVals
}

// DistroVersionMetadata contains distro versions
// This is not meant to be used directly. The distro version should be retrieved
// from the Ecosystem() function.
type DistroVersionMetadata struct {
	DistroVersionStr string
}
