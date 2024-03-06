package image

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/google/osv-scanner/pkg/lockfile"
)

// artifactExtractors contains only extractors for artifacts that are important in
// the final layer of a container image
var artifactExtractors map[string]lockfile.Extractor = map[string]lockfile.Extractor{
	"apk-installed": lockfile.ApkInstalledExtractor{},
	"dpkg":          lockfile.DpkgStatusExtractor{},
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
