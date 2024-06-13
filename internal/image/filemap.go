package image

import (
	"io/fs"
	"os"

	"github.com/dghubble/trie"
)

type fileType int

const (
	RegularFile fileType = iota
	Dir
)

// fileNode represents a file on a specific layer, mapping the contents to an extracted file on disk
type fileNode struct {
	fileType         fileType
	isWhiteout       bool
	absoluteDiskPath string
	virtualPath      string
	permission       fs.FileMode
}

// fileMap represents all the files on a layer
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
