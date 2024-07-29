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
