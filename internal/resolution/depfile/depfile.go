// Package depfile provides a temporary abstraction for files that have been opened for extraction.
// TODO(michaelkedar): This is used for guided remediation, and will be removed after the migration to OSV-Scalibr is complete.
package depfile

import (
	"io"
	"os"
	"path/filepath"
)

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
