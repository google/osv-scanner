// Package fakefs provides a fake file system implementation for testing.
package fakefs

import (
	"io/fs"
	"time"
)

// FakeFileInfo is a fake implementation of fs.FileInfo.
type FakeFileInfo struct {
	FileName    string
	FileSize    int64
	FileMode    fs.FileMode
	FileModTime time.Time
}

// Name returns the name of the file.
func (i FakeFileInfo) Name() string {
	return i.FileName
}

// Size returns the size of the file.
func (i FakeFileInfo) Size() int64 {
	return i.FileSize
}

// Mode returns the mode of the file.
func (i FakeFileInfo) Mode() fs.FileMode {
	return i.FileMode
}

// ModTime returns the modification time of the file.
func (i FakeFileInfo) ModTime() time.Time {
	return i.FileModTime
}

// IsDir returns true if the file is a directory.
func (i FakeFileInfo) IsDir() bool {
	return i.FileMode.IsDir()
}

// Sys is an implementation of FileInfo.Sys() that returns nothing (nil).
func (i FakeFileInfo) Sys() any {
	return nil
}
