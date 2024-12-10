package lockfilescalibr

import "errors"

var ErrIncompatibleFileFormat = errors.New("file format is incompatible, but this is expected")
var ErrNotImplemented = errors.New("not implemented")
var ErrWrongExtractor = errors.New("this extractor did not create this inventory")
var ErrExtractorNotFound = errors.New("could not determine extractor")
var ErrNoExtractorsFound = errors.New("no extractors found to be suitable to this file")
