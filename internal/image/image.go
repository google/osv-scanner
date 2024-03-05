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
	"sort"
	"strings"

	"github.com/dghubble/trie"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

const whiteoutPrefix = ".wh."

// 2 GB
const fileReadLimit = 2 * 1 << (10 * 3)

type ScanResults struct {
	Lockfiles []lockfile.Lockfile
	ImagePath string
}

// artifactExtractors contains only extractors for artifacts that are important in
// the final layer of a container image
var artifactExtractors map[string]lockfile.Extractor = map[string]lockfile.Extractor{
	"apk-installed": lockfile.ApkInstalledExtractor{},
	"dpkg":          lockfile.DpkgStatusExtractor{},
}

// ScanImage scans an exported docker image .tar file
func ScanImage(r reporter.Reporter, imagePath string) (ScanResults, error) {
	img, err := loadImage(imagePath)
	if err != nil {
		return ScanResults{}, fmt.Errorf("failed to open image %s: %w", imagePath, err)
	}

	allFiles := img.LastLayer().AllFiles()

	scannedLockfiles := ScanResults{
		ImagePath: imagePath,
	}
	for _, file := range allFiles {
		if file.fileType != RegularFile {
			continue
		}

		parsedLockfile, err := extractArtifactDeps(file.virtualPath, &img)
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)
	}

	err = img.Cleanup()
	if err != nil {
		err = fmt.Errorf("failed to cleanup: %w", img.Cleanup())
	}

	return scannedLockfiles, err
}

type Image struct {
	flattenedLayers []FileMap
	innerImage      *v1.Image
	extractDir      string
}

func (img *Image) LastLayer() *FileMap {
	return &img.flattenedLayers[len(img.flattenedLayers)-1]
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
		flattenedLayers: make([]FileMap, len(layers)),
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
		err = os.Mkdir(dirPath, 0755)
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

			var fileType FileType
			// write out the file/dir to disk
			switch header.Typeflag {
			case tar.TypeDir:
				if _, err := os.Stat(absoluteDiskPath); err != nil {
					if err := os.MkdirAll(absoluteDiskPath, 0600); err != nil {
						return Image{}, err
					}
				}
				fileType = Dir

			default: // Assume if it's not a directory, it's a normal file
				// Write all files as read/writable by the current user, inaccessible by anyone else
				// Actual permission bits are stored in FileNode
				f, err := os.OpenFile(absoluteDiskPath, os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					return Image{}, err
				}
				numBytes, err := io.Copy(f, io.LimitReader(tarReader, fileReadLimit))
				if numBytes >= fileReadLimit || errors.Is(err, io.EOF) {
					f.Close()
					return Image{}, fmt.Errorf("file exceeds read limit (potential decompression bomb attack)")
				}
				if err != nil {
					f.Close()
					return Image{}, fmt.Errorf("unable to copy file: %w", err)
				}
				fileType = RegularFile
				f.Close()
			}

			// Loop back up through the layers and add files
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

				currentMap.fileNodeTrie.Put(virtualPath, FileNode{
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

func inWhiteoutDir(fileMap FileMap, filePath string) bool {
	for {
		if filePath == "" {
			break
		}
		dirname := filepath.Dir(filePath)
		if filePath == dirname {
			break
		}
		val := fileMap.fileNodeTrie.Get(dirname)
		item, ok := val.(FileNode)
		if ok && item.isWhiteout {
			return true
		}
		filePath = dirname
	}

	return false
}

func findArtifactExtractor(path string) (lockfile.Extractor, string) {
	for name, extractor := range artifactExtractors {
		if extractor.ShouldExtract(path) {
			return extractor, name
		}
	}

	return nil, ""
}

func extractArtifactDeps(path string, img *Image) (lockfile.Lockfile, error) {
	extractor, extractedAs := findArtifactExtractor(path)

	if extractor == nil {
		return lockfile.Lockfile{}, fmt.Errorf("%w for %s", lockfile.ErrExtractorNotFound, path)
	}

	f, err := OpenImageFile(path, img)
	if err != nil {
		return lockfile.Lockfile{}, fmt.Errorf("attempted to open file but failed: %w", err)
	}

	defer f.Close()

	packages, err := extractor.Extract(f)
	if err != nil && extractedAs != "" {
		err = fmt.Errorf("(extracting as %s) %w", extractedAs, err)
		return lockfile.Lockfile{}, fmt.Errorf("failed to close file: %w", err)
	}

	// Sort to have deterministic output, and to match behavior of lockfile.extractDeps
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return lockfile.Lockfile{
		FilePath: f.Path(),
		ParsedAs: extractedAs,
		Packages: packages,
	}, err
}

// A ImageFile represents a file that exists in an image
type ImageFile struct {
	io.ReadCloser

	path string
}

func (f ImageFile) Open(path string) (lockfile.NestedDepFile, error) {
	// TODO: Implement this after interface change has been performed.
	return nil, errors.New("not implemented")
}

func (f ImageFile) Path() string {
	return f.path
}

func OpenImageFile(path string, img *Image) (ImageFile, error) {
	readCloser, err := img.LastLayer().OpenFile(path)

	if err != nil {
		return ImageFile{}, err
	}

	return ImageFile{
		ReadCloser: readCloser,
		path:       path,
	}, nil
}

var _ lockfile.DepFile = ImageFile{}
var _ lockfile.NestedDepFile = ImageFile{}
