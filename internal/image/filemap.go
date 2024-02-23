package image

import (
	"io/fs"
	"os"
	"path/filepath"
)

type FileType int

const (
	RegularFile FileType = iota
	Dir
)

type FileNode struct {
	fileType         FileType
	isWhiteout       bool
	relativeDiskPath string
	virtualPath      string
}

type FileMap struct {
	hashedKeys map[string]FileNode
}

func (filemap *FileMap) OpenFile(rootPath string, path string) (fs.File, error) {
	realPath := filepath.Join(rootPath, filemap.hashedKeys[path].relativeDiskPath)

	return os.Open(realPath)
}
