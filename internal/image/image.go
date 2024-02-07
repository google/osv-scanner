package image

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
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

var artifactExtractors map[string]lockfile.Extractor = map[string]lockfile.Extractor{
	"apk-installed": lockfile.ApkInstalledExtractor{},
	"dpkg":          lockfile.DpkgStatusExtractor{},
}

func ScanImage(imagePath string) (ScanResults, error) {
	ctx := context.Background() // TODO: use proper context
	img, err := stereoscope.GetImage(ctx, imagePath)

	fileTree := img.SquashedTree()
	allFiles := fileTree.AllFiles()

	slices.SortFunc(allFiles, func(a, b file.Reference) int {
		return strings.Compare(string(a.RealPath), string(b.RealPath))
	})

	r := reporter.NewTableReporter(os.Stdout, os.Stderr, reporter.VerboseLevel, false, 80)

	scannedLockfiles := ScanResults{
		ImagePath: imagePath,
	}
	for _, file := range allFiles {
		imgFile, err := OpenImageFile(string(file.RealPath), img, file)
		if err != nil {
			r.Errorf("Attempted to open file but failed: %s\n", err)
		}
		path := string(file.RealPath)
		parsedLockfile, err := lockfile.ExtractDeps(imgFile, "")
		if err != nil && !errors.Is(err, lockfile.ErrExtractorNotFound) {
			r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", path, err)
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)

		// No need to check for error
		// If scan fails, it means it isn't a valid SBOM file,
		// so just move onto the next file
		// pkgs, _ := scanSBOMFile(r, path, true)
		// scannedPackages = append(scannedPackages, pkgs...)
	}

	err = img.Cleanup()

	return scannedLockfiles, err
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
