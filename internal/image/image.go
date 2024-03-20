package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dghubble/trie"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scanner/pkg/lockfile"
)

const whiteoutPrefix = ".wh."

// 2 GB
const fileReadLimit = 2 * 1 << (10 * 3)
const dirPermission = 0700
const filePermission = 0600

type ScanResults struct {
	Lockfiles []lockfile.Lockfile
	ImagePath string
}

type Image struct {
	flattenedLayers []fileMap
	innerImage      *v1.Image
	extractDir      string
}

func (img *Image) LastLayer() fileMap {
	return img.flattenedLayers[len(img.flattenedLayers)-1]
}

func (img *Image) Cleanup() error {
	return os.RemoveAll(img.extractDir)
}

func loadImage(imagePath string) (Image, error) {
	image, err := tarball.ImageFromPath(imagePath, nil)
	if err != nil {
		return Image{}, err
	}

	tempPath, err := os.MkdirTemp("", "osv-scanner-image-scanning-*")
	if err != nil {
		return Image{}, err
	}

	layers, err := image.Layers()
	if err != nil {
		return Image{}, err
	}

	outputImage := Image{
		extractDir:      tempPath,
		innerImage:      &image,
		flattenedLayers: make([]fileMap, len(layers)),
	}

	// Reverse loop through the layers to start from the latest layer first
	// this allows us to skip all files already seen
	for i := len(layers) - 1; i >= 0; i-- {
		hash, err := layers[i].DiffID()
		hashStr := strings.TrimPrefix(hash.String(), "sha256:")
		if err != nil {
			return Image{}, err
		}

		dirPath := filepath.Join(tempPath, hashStr)
		err = os.Mkdir(dirPath, dirPermission)
		if err != nil {
			return Image{}, err
		}

		layerReader, err := layers[i].Uncompressed()
		if err != nil {
			return Image{}, err
		}
		defer layerReader.Close()
		tarReader := tar.NewReader(layerReader)

		for {
			header, err := tarReader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return Image{}, fmt.Errorf("reading tar: %w", err)
			}
			// Some tools prepend everything with "./", so if we don't Clean the
			// name, we may have duplicate entries, which angers tar-split.
			// Using path instead of filepath to keep `/` and deterministic behavior
			cleanedFilePath := path.Clean(header.Name)
			// Prevent "Zip Slip"
			if strings.HasPrefix(cleanedFilePath, "../") {
				// TODO: Could this occur with a normal image?
				// e.g. maybe a bad symbolic link?
				// and should we warn the user that some files are ignored
				continue
			}
			// force PAX format to remove Name/Linkname length limit of 100 characters
			// required by USTAR and to not depend on internal tar package guess which
			// prefers USTAR over PAX
			header.Format = tar.FormatPAX

			basename := path.Base(cleanedFilePath)
			dirname := path.Dir(cleanedFilePath)
			tombstone := strings.HasPrefix(basename, whiteoutPrefix)
			if tombstone { // TODO: Handle Opaque Whiteouts
				basename = basename[len(whiteoutPrefix):]
			}

			// check if we have seen value before
			// if we're checking a directory, don't filepath.Join names
			var virtualPath string
			if header.Typeflag == tar.TypeDir {
				virtualPath = "/" + cleanedFilePath
			} else {
				virtualPath = "/" + path.Join(dirname, basename)
			}

			// where the file will be written to disk
			// filepath.Clean first to convert to OS specific file path
			// TODO: Escape invalid characters on windows that's valid on linux
			absoluteDiskPath := filepath.Join(dirPath, filepath.Clean(cleanedFilePath))

			var fileType fileType
			// write out the file/dir to disk
			switch header.Typeflag {
			case tar.TypeDir:
				if _, err := os.Stat(absoluteDiskPath); err != nil {
					if err := os.MkdirAll(absoluteDiskPath, dirPermission); err != nil {
						return Image{}, err
					}
				}
				fileType = Dir

			default: // Assume if it's not a directory, it's a normal file
				// Write all files as read/writable by the current user, inaccessible by anyone else
				// Actual permission bits are stored in FileNode
				f, err := os.OpenFile(absoluteDiskPath, os.O_CREATE|os.O_RDWR, filePermission)
				if err != nil {
					return Image{}, err
				}
				numBytes, err := io.Copy(f, io.LimitReader(tarReader, fileReadLimit))
				if numBytes >= fileReadLimit || errors.Is(err, io.EOF) {
					f.Close()
					return Image{}, errors.New("file exceeds read limit (potential decompression bomb attack)")
				}
				if err != nil {
					f.Close()
					return Image{}, fmt.Errorf("unable to copy file: %w", err)
				}
				fileType = RegularFile
				f.Close()
			}

			// Each outer loop, we add a layer to each relevant output flattenedLayers slice
			// Because we are looping backwards in the outer loop (latest layer first)
			// We ignore any files that's already in each flattenedLayer, as they would
			// have been overwritten.
			for ii := i; ii < len(layers); ii++ {
				currentMap := &outputImage.flattenedLayers[ii]
				if currentMap.fileNodeTrie == nil {
					currentMap.fileNodeTrie = trie.NewPathTrie()
				}

				if item := currentMap.fileNodeTrie.Get(virtualPath); item != nil {
					// File already exists in a later layer
					continue
				}

				// check for a whited out parent directory
				if inWhiteoutDir(*currentMap, virtualPath) {
					continue
				}

				currentMap.fileNodeTrie.Put(virtualPath, fileNode{
					virtualPath:      virtualPath,
					absoluteDiskPath: absoluteDiskPath,
					fileType:         fileType,
					isWhiteout:       tombstone,
					permission:       fs.FileMode(header.Mode),
				})
			}
		}
		// TODO: Cleanup temporary dir as there will be leftovers on errors
	}

	return outputImage, nil
}

func inWhiteoutDir(fileMap fileMap, filePath string) bool {
	for {
		if filePath == "" {
			break
		}
		dirname := filepath.Dir(filePath)
		if filePath == dirname {
			break
		}
		val := fileMap.fileNodeTrie.Get(dirname)
		item, ok := val.(fileNode)
		if ok && item.isWhiteout {
			return true
		}
		filePath = dirname
	}

	return false
}
