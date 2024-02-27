package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

const whiteoutPrefix = ".wh."

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
	// ctx := context.Background() // TODO: use proper context
	// img, err := stereoscope.GetImage(ctx, imagePath)
	img, err := loadImage(imagePath)
	if err != nil {
		return ScanResults{}, fmt.Errorf("failed to open image %s: %w", imagePath, err)
	}

	allFiles := img.AllFiles()

	// Sort the files to:
	//   - Easier reasoning when debugging the scan loop
	//   - Allow us to find "folders", as allFiles only contain file references
	//     we have to examine the path of the files for folders. (Not yet implemented)
	// slices.SortFunc(allFiles, func(a, b file.Reference) int {
	// 	return strings.Compare(string(a.RealPath), string(b.RealPath))
	// })

	scannedLockfiles := ScanResults{
		ImagePath: imagePath,
	}
	for _, file := range allFiles {
		if file.fileType != RegularFile {
			continue
		}

		imgFile, err := OpenImageFile(file.virtualPath, &img)
		if err != nil {
			r.Errorf("Attempted to open file but failed: %s\n", err)
		}
		parsedLockfile, err := extractArtifactDeps(imgFile)
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)
	}

	err = img.Cleanup()

	return scannedLockfiles, err
}

type Image struct {
	flattenedFileMaps []FileMap
	innerImage        *v1.Image
	tempDir           string
	manifest          *v1.Manifest
}

func (img *Image) ReadFile(virtualPath string) (fs.File, error) {
	return img.flattenedFileMaps[len(img.flattenedFileMaps)-1].OpenFile(img.tempDir, virtualPath)
}

func (img *Image) AllFiles() []FileNode {
	allFiles := []FileNode{}
	for _, fn := range img.flattenedFileMaps[len(img.flattenedFileMaps)-1].hashedKeys {
		if !fn.isWhiteout {
			allFiles = append(allFiles, fn)
		}
	}

	return allFiles
}

func (img *Image) Cleanup() error {
	return os.RemoveAll(img.tempDir)
}

func loadImage(path string) (Image, error) {
	image, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return Image{}, err
	}

	tempPath, err := os.MkdirTemp("", "osv-scanner-image-scanning-*")
	if err != nil {
		return Image{}, err
	}

	manifest, err := image.Manifest()
	if err != nil {
		return Image{}, err
	}

	layers, err := image.Layers()
	if err != nil {
		return Image{}, err
	}

	outputImage := Image{
		tempDir:           tempPath,
		manifest:          manifest,
		flattenedFileMaps: make([]FileMap, len(layers)),
	}

	// Reverse loop through the layers to start from the latest layer first
	// this allows us to skip all files already seen
	for i := len(layers) - 1; i >= 0; i-- {
		hash, err := layers[i].Digest()
		if err != nil {
			return Image{}, err
		}

		dirPath := filepath.Join(tempPath, hash.String())
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
			header.Name = filepath.Clean(header.Name)
			// force PAX format to remove Name/Linkname length limit of 100 characters
			// required by USTAR and to not depend on internal tar package guess which
			// prefers USTAR over PAX
			header.Format = tar.FormatPAX

			basename := filepath.Base(header.Name)
			dirname := filepath.Dir(header.Name)
			tombstone := strings.HasPrefix(basename, whiteoutPrefix)
			if tombstone { // TODO: Handle Opaque Whiteouts
				basename = basename[len(whiteoutPrefix):]
			}

			// check if we have seen value before
			// if we're checking a directory, don't filepath.Join names
			var virtualPath string
			if header.Typeflag == tar.TypeDir {
				virtualPath = "/" + header.Name
			} else {
				virtualPath = "/" + filepath.Join(dirname, basename)
			}

			// where the file will be written to disk
			diskTargetPath := filepath.Join(dirPath, header.Name)

			var fileType FileType = RegularFile
			// write out the file/dir to disk
			switch header.Typeflag {
			case tar.TypeDir:
				if _, err := os.Stat(diskTargetPath); err != nil {
					if err := os.MkdirAll(diskTargetPath, 0755); err != nil {
						return Image{}, err
					}
				}
				fileType = Dir

			default: // Assume if it's not a directory, it's a normal file
				f, err := os.OpenFile(diskTargetPath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
				if err != nil {
					return Image{}, err
				}

				if _, err := io.Copy(f, tarReader); err != nil {
					return Image{}, err
				}
				fileType = RegularFile
				f.Close()
			}

			// Remove temporary directory name from the filemap path
			// These paths will be joined together again when opening files
			fileMapDiskPath := strings.TrimPrefix(diskTargetPath, tempPath)

			// Loop back up through the layers and add files
			for ii := i; ii < len(layers); ii++ {
				currentMap := &outputImage.flattenedFileMaps[ii]
				if currentMap.hashedKeys == nil {
					currentMap.hashedKeys = map[string]FileNode{}
				}

				if _, ok := currentMap.hashedKeys[virtualPath]; ok {
					// File already exists in a later layer
					continue
				}

				// check for a whited out parent directory
				if inWhiteoutDir(*currentMap, virtualPath) {
					continue
				}

				currentMap.hashedKeys[virtualPath] = FileNode{
					virtualPath:      virtualPath,
					relativeDiskPath: fileMapDiskPath,
					fileType:         fileType,
					isWhiteout:       tombstone,
				}
			}
		}

		if err != nil { // TODO: Cleanup temporary dir as there will be leftovers on errors
			return Image{}, err
		}
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
		if val, ok := fileMap.hashedKeys[dirname]; ok && val.isWhiteout {
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

func extractArtifactDeps(f lockfile.DepFile) (lockfile.Lockfile, error) {
	extractor, extractedAs := findArtifactExtractor(f.Path())

	if extractor == nil {
		return lockfile.Lockfile{}, fmt.Errorf("%w for %s", lockfile.ErrExtractorNotFound, f.Path())
	}

	packages, err := extractor.Extract(f)
	if err != nil && extractedAs != "" {
		err = fmt.Errorf("(extracting as %s) %w", extractedAs, err)
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
	return nil, errors.New("not implemented")
}

func (f ImageFile) Path() string {
	return f.path
}

func OpenImageFile(path string, img *Image) (ImageFile, error) {
	readcloser, err := img.ReadFile(path)

	if err != nil {
		return ImageFile{}, err
	}

	return ImageFile{
		ReadCloser: readcloser,
		path:       path,
	}, nil
}

var _ lockfile.DepFile = ImageFile{}
var _ lockfile.NestedDepFile = ImageFile{}
