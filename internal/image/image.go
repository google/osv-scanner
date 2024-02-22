package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

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
	ctx := context.Background() // TODO: use proper context
	img, err := stereoscope.GetImage(ctx, imagePath)
	if err != nil {
		return ScanResults{}, fmt.Errorf("failed to open image %s: %w", imagePath, err)
	}

	fileTree := img.SquashedTree()
	allFiles := fileTree.AllFiles()

	// Sort the files to:
	//   - Easier reasoning when debugging the scan loop
	//   - Allow us to find "folders", as allFiles only contain file references
	//     we have to examine the path of the files for folders. (Not yet implemented)
	slices.SortFunc(allFiles, func(a, b file.Reference) int {
		return strings.Compare(string(a.RealPath), string(b.RealPath))
	})

	scannedLockfiles := ScanResults{
		ImagePath: imagePath,
	}
	for _, file := range allFiles {
		imgFile, err := OpenImageFile(string(file.RealPath), img, file)
		if err != nil {
			r.Errorf("Attempted to open file but failed: %s\n", err)
		}
		path := string(file.RealPath)
		parsedLockfile, err := extractArtifactDeps(imgFile)
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", path, err)
			}

			continue
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)
	}

	err = img.Cleanup()

	return scannedLockfiles, err
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

func OpenImageFile(path string, img *image.Image, fileRef file.Reference) (ImageFile, error) {
	readcloser, err := img.FileContentsByRef(fileRef)

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
