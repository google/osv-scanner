package image

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/osv-scanner/internal/image/thirdparty/trie"
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

var _ fs.DirEntry = FileNode{}

func (f FileNode) IsDir() bool {
	return f.fileType == Dir
}

func (f FileNode) Name() string {
	return filepath.Base(f.virtualPath)
}

func (f FileNode) Type() fs.FileMode {
	return f.permission
}

func (f FileNode) Info() (fs.FileInfo, error) {
	return f.Stat()
}

type FileNodeFileInfo struct {
	baseFileInfo fs.FileInfo
	fileNode     *FileNode
}

var _ fs.FileInfo = FileNodeFileInfo{}

func (f FileNodeFileInfo) Name() string {
	return filepath.Base(f.fileNode.virtualPath)
}

func (f FileNodeFileInfo) Size() int64 {
	return f.baseFileInfo.Size()
}

func (f FileNodeFileInfo) Mode() fs.FileMode {
	return f.fileNode.permission
}

func (f FileNodeFileInfo) ModTime() time.Time {
	return f.baseFileInfo.ModTime()
}

func (f FileNodeFileInfo) IsDir() bool {
	return f.fileNode.fileType == Dir
}

func (f FileNodeFileInfo) Sys() any {
	return nil
}

// Stat returns the FileInfo structure describing file.
func (f *FileNode) Stat() (fs.FileInfo, error) {
	baseFileInfo, err := os.Stat(f.absoluteDiskPath())
	if err != nil {
		return nil, err
	}

	return FileNodeFileInfo{
		baseFileInfo: baseFileInfo,
		fileNode:     f,
	}, nil
}

// Open returns a file handle for the file
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
	fileNodeTrie *trie.PathTrie
	rootImage    *Image
	// TODO: Use hashmap to speed up path lookups
}

func (filemap Layer) Open(path string) (fs.File, error) {
	node, ok := filemap.fileNodeTrie.Get(path).(FileNode)
	if !ok {
		return nil, fs.ErrNotExist
	}

	return node.Open()
}

func (filemap Layer) Stat(path string) (fs.FileInfo, error) {
	node, ok := filemap.fileNodeTrie.Get(path).(FileNode)
	if !ok {
		return nil, fs.ErrNotExist
	}

	return node.Stat()
}

func (filemap Layer) ReadDir(path string) ([]fs.DirEntry, error) {
	output := []fs.DirEntry{}
	err := filemap.fileNodeTrie.WalkChildren(path, func(path string, value interface{}) error {
		if value == nil {
			panic("TODO: Unexpected, corrupted tar?, we should be storing all directories")
		}

		output = append(output, value.(FileNode))

		return nil
	})

	if err != nil {
		return []fs.DirEntry{}, err
	}

	return output, nil
}

var _ fs.FS = Layer{}
var _ fs.StatFS = Layer{}
var _ fs.ReadDirFS = Layer{}

func (filemap Layer) getFileNode(path string) (FileNode, error) {
	node, ok := filemap.fileNodeTrie.Get(path).(FileNode)
	if !ok {
		return FileNode{}, fs.ErrNotExist
	}

	return node, nil
}

// AllFiles return all files that exist on the layer the FileMap is representing
func (filemap Layer) AllFiles() []FileNode {
	allFiles := []FileNode{}
	// No need to check error since we are not returning any errors
	_ = filemap.fileNodeTrie.Walk(func(_ string, value interface{}) error {
		node := value.(FileNode)
		if node.fileType != RegularFile { // Only add regular files
			return nil
		}

		if node.isWhiteout { // Don't add whiteout files as they have been deleted
			return nil
		}

		allFiles = append(allFiles, value.(FileNode))

		return nil
	})

	return allFiles
}
