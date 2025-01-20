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

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scanner/internal/image/pathtree"
	"github.com/google/osv-scanner/pkg/lockfile"
)

const whiteoutPrefix = ".wh."

// 2 GB
const fileReadLimit = 2 * 1 << (10 * 3)
const dirPermission = 0700
const filePermission = 0600

var ErrNoHistoryAvailable = errors.New("no history available")

type ScanResults struct {
	Lockfiles []lockfile.Lockfile
	ImagePath string
}

type Image struct {
	// Final layer is the last element in the slice
	layers         []Layer
	innerImage     *v1.Image
	extractDir     string
	baseImageIndex int
	configFile     *v1.ConfigFile
	layerIDToIndex map[string]int
}

// layerIDToCommand takes in a layer id (see imgLayer.id) and returns the history CreatedBy field
// of the corresponding layer
func (img *Image) layerIDToCommand(id string) (string, error) {
	idxCount := img.layerIDToIndex[id]
	var i int
	// Match history to layer IDX by skipping empty layer history entries
	for i = 0; idxCount >= 0; i++ {
		if i >= len(img.configFile.History) {
			return "", ErrNoHistoryAvailable
		}

		if img.configFile.History[i].EmptyLayer {
			continue
		}
		idxCount -= 1
	}
	// -1 from i because when idxCount becomes -1 it still increments i by 1
	return img.configFile.History[i-1].CreatedBy, nil
}

func (img *Image) LastLayer() *Layer {
	return &img.layers[len(img.layers)-1]
}

func (img *Image) Cleanup() error {
	if img == nil {
		return errors.New("image is nil")
	}

	return os.RemoveAll(img.extractDir)
}

func LoadImage(imagePath string) (*Image, error) {
	image, err := tarball.ImageFromPath(imagePath, nil)
	if err != nil {
		return nil, err
	}

	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}

	configFile, err := image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	tempPath, err := os.MkdirTemp("", "osv-scanner-image-scanning-*")
	if err != nil {
		return nil, err
	}

	outputImage := Image{
		extractDir:     tempPath,
		innerImage:     &image,
		layers:         make([]Layer, len(layers)),
		layerIDToIndex: make(map[string]int),
		configFile:     configFile,
		baseImageIndex: guessBaseImageIndex(configFile.History),
	}

	// Initiate the layers first
	for i := range layers {
		hash, err := layers[i].DiffID()
		if err != nil {
			// Return the partial image so that the temporary path folder can be cleaned up
			return &outputImage, err
		}

		outputImage.layers[i] = Layer{
			fileNodeTrie: pathtree.NewNode[FileNode](),
			id:           hash.Hex,
			rootImage:    &outputImage,
		}

		outputImage.layerIDToIndex[hash.Hex] = i
	}

	// Reverse loop through the layers to start from the latest layer first
	// this allows us to skip all files already seen
	for i := len(layers) - 1; i >= 0; i-- {
		dirPath := filepath.Join(tempPath, outputImage.layers[i].id)
		err = os.Mkdir(dirPath, dirPermission)
		if err != nil {
			return &outputImage, err
		}

		layerReader, err := layers[i].Uncompressed()
		if err != nil {
			return &outputImage, err
		}

		tarReader := tar.NewReader(layerReader)

		for {
			header, err := tarReader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return &outputImage, fmt.Errorf("reading tar: %w", err)
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
						return &outputImage, err
					}
				}
				fileType = Dir

			default: // Assume if it's not a directory, it's a normal file
				// Write all files as read/writable by the current user, inaccessible by anyone else
				// Actual permission bits are stored in FileNode
				f, err := os.OpenFile(absoluteDiskPath, os.O_CREATE|os.O_RDWR, filePermission)
				if err != nil {
					return &outputImage, err
				}
				numBytes, err := io.Copy(f, io.LimitReader(tarReader, fileReadLimit))
				if numBytes >= fileReadLimit || errors.Is(err, io.EOF) {
					f.Close()
					return &outputImage, errors.New("file exceeds read limit (potential decompression bomb attack)")
				}
				if err != nil {
					f.Close()
					return &outputImage, fmt.Errorf("unable to copy file: %w", err)
				}
				fileType = RegularFile
				f.Close()
			}

			// Each outer loop, we add a layer to each relevant output flattenedLayers slice
			// Because we are looping backwards in the outer loop (latest layer first)
			// we ignore any files that's already in each flattenedLayer, as they would
			// have been overwritten.
			//
			// This loop will add the file to all future layers if it doesn't already exist
			// (i.e. hasn't been overwritten)
			for ii := i; ii < len(layers); ii++ {
				currentMap := &outputImage.layers[ii]

				if item := currentMap.fileNodeTrie.Get(virtualPath); item != nil {
					// A newer version of the file already exists on a later map.
					// Since we do not want to overwrite a later layer with information
					// written in an earlier layer, skip this file.
					continue
				}

				// check for a whited out parent directory
				if inWhiteoutDir(*currentMap, virtualPath) {
					// The entire directory has been deleted, so no need to save this file
					continue
				}

				err := currentMap.fileNodeTrie.Insert(virtualPath, &FileNode{
					rootImage: &outputImage,
					// Select the original layer of the file
					originLayer: &outputImage.layers[i],
					virtualPath: virtualPath,
					fileType:    fileType,
					isWhiteout:  tombstone,
					permission:  fs.FileMode(header.Mode), //nolint:gosec
				})

				if err != nil {
					return &outputImage, fmt.Errorf("image tar has repeated files: %w", err)
				}
			}
		}

		// Manually close at the end of the for loop
		// We don't want to defer because then no layers will be closed until entire image is read
		layerReader.Close()
	}

	return &outputImage, nil
}

func inWhiteoutDir(fileMap Layer, filePath string) bool {
	for {
		if filePath == "" {
			break
		}
		dirname := path.Dir(filePath)
		if filePath == dirname {
			break
		}
		node := fileMap.fileNodeTrie.Get(dirname)
		if node != nil && node.isWhiteout {
			return true
		}
		filePath = dirname
	}

	return false
}
