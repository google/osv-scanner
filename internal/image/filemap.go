package image

import (
	"io/fs"
	"os"

	"github.com/dghubble/trie"
)

type FileType int

const (
	RegularFile FileType = iota
	Dir
)

type FileNode struct {
	fileType         FileType
	isWhiteout       bool
	absoluteDiskPath string
	virtualPath      string
}

type FileMap struct {
	fileNodeTrie *trie.PathTrie
	// TODO: Use hashset to speed up path lookups
}

func (filemap *FileMap) OpenFile(path string) (fs.File, error) {
	node, ok := filemap.fileNodeTrie.Get(path).(FileNode)
	if !ok {
		return nil, fs.ErrNotExist
	}

	return os.Open(node.absoluteDiskPath)
}

func (filemap *FileMap) AllFiles() []FileNode {
	allFiles := []FileNode{}
	// No need to check error since we are not returning any errors
	_ = filemap.fileNodeTrie.Walk(func(key string, value interface{}) error {
		allFiles = append(allFiles, value.(FileNode))
		return nil
	})

	return allFiles
}
