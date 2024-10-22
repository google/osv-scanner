package lockfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrOpenNotSupported = errors.New("this file does not support opening files")

// DepFile is an abstraction for a file that has been opened for extraction,
// and that knows how to open other DepFiles relative to itself.
type DepFile interface {
	io.Reader

	// Open opens an NestedDepFile based on the path of the
	// current DepFile if the provided path is relative.
	//
	// If the path is an absolute path, then it is opened absolutely.
	Open(path string) (NestedDepFile, error)

	Path() string
}

// NestedDepFile is an abstraction for a file that has been opened while extracting another file,
// and would need to be closed.
type NestedDepFile interface {
	io.Closer
	DepFile
}

type Extractor interface {
	// ShouldExtract checks if the Extractor should be used for the given path.
	ShouldExtract(path string) bool
	Extract(f DepFile) ([]PackageDetails, error)
}

// A LocalFile represents a file that exists on the local filesystem.
type LocalFile struct {
	// TODO(rexpan): This should be *os.File, as that would allow us to access other underlying functions that definitely will exist
	io.ReadCloser

	path string
}

func (f LocalFile) Open(path string) (NestedDepFile, error) {
	if filepath.IsAbs(path) {
		return OpenLocalDepFile(path)
	}

	return OpenLocalDepFile(filepath.Join(filepath.Dir(f.path), path))
}

func (f LocalFile) Path() string { return f.path }

func OpenLocalDepFile(path string) (NestedDepFile, error) {
	r, err := os.Open(path)

	if err != nil {
		return LocalFile{}, err
	}

	// Very unlikely to have Abs return an error if the file opens correctly
	path, _ = filepath.Abs(path)

	return LocalFile{r, path}, nil
}

var _ DepFile = LocalFile{}
var _ NestedDepFile = LocalFile{}

func extractFromFile(pathToLockfile string, extractor Extractor) ([]PackageDetails, error) {
	f, err := OpenLocalDepFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, err
	}

	defer f.Close()

	return extractor.Extract(f)
}
