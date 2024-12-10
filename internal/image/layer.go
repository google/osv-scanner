package image

import (
	"io/fs"
	"os"
	"strings"
	"time"

	// Note that paths accessing the disk must use filepath, but all virtual paths should use path
	"path"
	"path/filepath"

	"github.com/google/osv-scanner/internal/image/pathtree"
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

var _ fs.DirEntry = &FileNode{}

func (f *FileNode) IsDir() bool {
	return f.fileType == Dir
}

func (f *FileNode) Name() string {
	return path.Base(f.virtualPath)
}

func (f *FileNode) Type() fs.FileMode {
	return f.permission
}

func (f *FileNode) Info() (fs.FileInfo, error) {
	return f.Stat()
}

type FileNodeFileInfo struct {
	baseFileInfo fs.FileInfo
	fileNode     *FileNode
}

var _ fs.FileInfo = FileNodeFileInfo{}

func (f FileNodeFileInfo) Name() string {
	return path.Base(f.fileNode.virtualPath)
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
	fileNodeTrie *pathtree.Node[FileNode]
	rootImage    *Image
	// TODO: Use hashmap to speed up path lookups
}

func (filemap Layer) Open(path string) (fs.File, error) {
	node, err := filemap.getFileNode(path)
	if err != nil {
		return nil, err
	}

	return node.Open()
}

func (filemap Layer) Stat(path string) (fs.FileInfo, error) {
	node, err := filemap.getFileNode(path)
	if err != nil {
		return nil, err
	}

	return node.Stat()
}

func (filemap Layer) ReadDir(path string) ([]fs.DirEntry, error) {
	children := filemap.fileNodeTrie.GetChildren(path)
	output := make([]fs.DirEntry, 0, len(children))
	for _, node := range children {
		output = append(output, node)
	}

	return output, nil
}

var _ fs.FS = Layer{}
var _ fs.StatFS = Layer{}
var _ fs.ReadDirFS = Layer{}

func (filemap Layer) getFileNode(nodePath string) (*FileNode, error) {
	// We expect all paths queried to be absolute paths rooted at the container root
	// However, scalibr uses paths without a prepending /, because the paths are relative to Root.
	// Root will always be '/' for container scanning, so prepend with / if necessary.
	if !strings.HasPrefix(nodePath, "/") {
		nodePath = path.Join("/", nodePath)
	}

	node := filemap.fileNodeTrie.Get(nodePath)
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
