package lockfilescalibr

import (
	"errors"
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

type DepGroups interface {
	DepGroups() []string
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
