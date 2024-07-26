package image

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/internal/image/thirdparty/trie"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

type fileType int

const (
	RegularFile fileType = iota
	Dir
)

// fileNode represents a file on a specific layer, mapping the contents to an extracted file on disk
// implements DirEntry
type fileNode struct {
	fileType         fileType
	isWhiteout       bool
	absoluteDiskPath string
	virtualPath      string
	permission       fs.FileMode
}

var _ fs.DirEntry = fileNode{}

func (fn fileNode) Name() string {
	return filepath.Base(fn.virtualPath)
}

func (fn fileNode) IsDir() bool {
	return fn.fileType == Dir
}

func (fn fileNode) Type() fs.FileMode {
	return fn.permission
}

func (fn fileNode) Info() (fs.FileInfo, error) {
	return os.Stat(fn.absoluteDiskPath)
}

// fileMap represents all the files on a layer
// implements a FS interface for opening files
type fileMap struct {
	fileNodeTrie *trie.PathTrie
	// TODO: Use hashset to speed up path lookups
}

func (filemap fileMap) OpenFile(path string) (*os.File, error) {
	node, ok := filemap.fileNodeTrie.Get(path).(fileNode)
	if !ok {
		return nil, fs.ErrNotExist
	}

	return os.Open(node.absoluteDiskPath)
}

// AllFiles return all files that exist on the layer the FileMap is representing
func (filemap fileMap) AllFiles() []fileNode {
	allFiles := []fileNode{}
	// No need to check error since we are not returning any errors
	_ = filemap.fileNodeTrie.Walk(func(key string, value interface{}) error {
		node := value.(fileNode)
		if node.fileType != RegularFile { // Only add regular files
			return nil
		}

		allFiles = append(allFiles, value.(fileNode))

		return nil
	})

	return allFiles
}

func (filemap fileMap) Open(name string) (fs.File, error) {
	// name has to be an absolute path, and FS paths does not being with /
	node, ok := filemap.fileNodeTrie.Get(filepath.Join("/", name)).(fileNode)
	if !ok {
		return nil, fs.ErrNotExist
	}
	// TODO: This is technically invalid, since calling Stat() will return the wrong values
	// fileNode itself should be a fs.File
	return os.Open(node.absoluteDiskPath)
}

// TODO: currently no error is returned when directory doesn't exist
func (filemap fileMap) ReadDir(name string) ([]fs.DirEntry, error) {
	output := []fs.DirEntry{}
	err := filemap.fileNodeTrie.WalkChildren(name, func(path string, value interface{}) error {
		if value == nil {
			panic("TODO: Unexpected, corrupted tar?, we should be storing all directories")
		}

		output = append(output, value.(fileNode))

		return nil
	})

	if err != nil {
		return []fs.DirEntry{}, err
	}

	return output, nil
}

func (filemap fileMap) Stat(name string) (fs.FileInfo, error) {
	node, ok := filemap.fileNodeTrie.Get(name).(fileNode)
	if !ok {
		return nil, fs.ErrNotExist
	}

	return node.Info()
}

var _ lockfilescalibr.FS = fileMap{}
