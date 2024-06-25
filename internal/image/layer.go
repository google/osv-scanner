package image

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/dghubble/trie"
)

type fileType int

const (
	RegularFile fileType = iota
	Dir
)

// fileNode represents a file on a specific layer, mapping the contents to an extracted file on disk
type fileNode struct {
	// TODO: Determine the performance implications of having a pointer to base image in every fileNode
	rootImage   *Image
	fileType    fileType
	isWhiteout  bool
	originLayer *imgLayer
	virtualPath string
	permission  fs.FileMode
}

func (f *fileNode) Open() (*os.File, error) {
	if f.isWhiteout {
		return nil, fs.ErrNotExist
	}

	return os.Open(f.absoluteDiskPath())
}

func (f *fileNode) absoluteDiskPath() string {
	return filepath.Join(f.rootImage.extractDir, f.originLayer.id, f.virtualPath)
}

// imgLayer represents all the files on a layer
type imgLayer struct {
	fileNodeTrie *trie.PathTrie
	id           string
	rootImage    *Image
	// TODO: Use hashmap to speed up path lookups
}

func (filemap imgLayer) GetFileNode(path string) (fileNode, error) {
	node, ok := filemap.fileNodeTrie.Get(path).(fileNode)
	if !ok {
		return fileNode{}, fs.ErrNotExist
	}

	return node, nil
}

// AllFiles return all files that exist on the layer the FileMap is representing
func (filemap imgLayer) AllFiles() []fileNode {
	allFiles := []fileNode{}
	// No need to check error since we are not returning any errors
	_ = filemap.fileNodeTrie.Walk(func(key string, value interface{}) error {
		node := value.(fileNode)
		if node.fileType != RegularFile { // Only add regular files
			return nil
		}

		if node.isWhiteout { // Don't add whiteout files as they have been deleted
			return nil
		}

		allFiles = append(allFiles, value.(fileNode))

		return nil
	})

	return allFiles
}
