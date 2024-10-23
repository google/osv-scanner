package image

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/internal/image/internal/pathtree"
)

type fileType int

const (
	RegularFile fileType = iota
	Dir
)

// FileNode represents a file on a specific layer, mapping the contents to an extracted file on disk
type FileNode struct {
	// TODO: Determine the performance implications of having a pointer to base image in every fileNode
	rootImage   *Image
	fileType    fileType
	isWhiteout  bool
	originLayer *Layer
	virtualPath string
	permission  fs.FileMode
}

func (f *FileNode) Open() (*os.File, error) {
	if f.isWhiteout {
		return nil, fs.ErrNotExist
	}

	return os.Open(f.absoluteDiskPath())
}

func (f *FileNode) absoluteDiskPath() string {
	return filepath.Join(f.rootImage.extractDir, f.originLayer.id, f.virtualPath)
}

// Layer represents all the files on a layer
type Layer struct {
	// id is the sha256 digest of the layer
	id           string
	fileNodeTrie *pathtree.Node[FileNode]
	rootImage    *Image
	// TODO: Use hashmap to speed up path lookups
}

func (filemap Layer) getFileNode(path string) (*FileNode, error) {
	node := filemap.fileNodeTrie.Get(path)
	if node == nil {
		return nil, fs.ErrNotExist
	}

	return node, nil
}

// AllFiles return all files that exist on the layer the FileMap is representing
func (filemap Layer) AllFiles() []*FileNode {
	allFiles := []*FileNode{}
	// No need to check error since we are not returning any errors
	_ = filemap.fileNodeTrie.Walk(func(_ string, node *FileNode) error {
		if node.fileType != RegularFile { // Only add regular files
			return nil
		}

		// TODO: Check if parent is an opaque whiteout
		if node.isWhiteout { // Don't add whiteout files as they have been deleted
			return nil
		}

		allFiles = append(allFiles, node)

		return nil
	})

	return allFiles
}
