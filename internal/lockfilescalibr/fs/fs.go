package fs

import "io/fs"

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
