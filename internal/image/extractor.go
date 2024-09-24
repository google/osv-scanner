package image

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/google/osv-scanner/pkg/lockfile"
)

// artifactExtractors contains only extractors for artifacts that are important in
// the final layer of a container image
var artifactExtractors map[string]lockfile.Extractor = map[string]lockfile.Extractor{
	"node_modules":  lockfile.NodeModulesExtractor{},
	"apk-installed": lockfile.ApkInstalledExtractor{},
	"dpkg":          lockfile.DpkgStatusExtractor{},
	"go-binary":     lockfile.GoBinaryExtractor{},
}

type extractorPair struct {
	extractor lockfile.Extractor
	name      string
}

func findArtifactExtractor(path string) []extractorPair {
	// Use ShouldExtract to collect and return a slice of artifactExtractors
	var extractors []extractorPair
	for name, extractor := range artifactExtractors {
		if extractor.ShouldExtract(path) {
			extractors = append(extractors, extractorPair{extractor, name})
		}
	}

	return extractors
}

func extractArtifactDeps(path string, layer *Layer) (lockfile.Lockfile, error) {
	foundExtractors := findArtifactExtractor(path)
	if len(foundExtractors) == 0 {
		return lockfile.Lockfile{}, fmt.Errorf("%w for %s", lockfile.ErrExtractorNotFound, path)
	}

	packages := []lockfile.PackageDetails{}
	var extractedAs string
	for _, extPair := range foundExtractors {
		// File has to be reopened per extractor as each extractor moves the read cursor
		f, err := OpenLayerFile(path, layer)
		if err != nil {
			return lockfile.Lockfile{}, fmt.Errorf("attempted to open file but failed: %w", err)
		}

		newPackages, err := extPair.extractor.Extract(f)
		f.Close()

		if err != nil {
			if errors.Is(err, lockfile.ErrIncompatibleFileFormat) {
				continue
			}

			return lockfile.Lockfile{}, fmt.Errorf("(extracting as %s) %w", extPair.name, err)
		}

		extractedAs = extPair.name
		packages = newPackages
		// TODO(rexpan): Determine if it's acceptable to have multiple extractors
		// extract from the same file successfully
		break
	}

	if extractedAs == "" {
		return lockfile.Lockfile{}, fmt.Errorf("%w for %s", lockfile.ErrExtractorNotFound, path)
	}

	// Sort to have deterministic output, and to match behavior of lockfile.extractDeps
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return lockfile.Lockfile{
		FilePath: path,
		ParsedAs: extractedAs,
		Packages: packages,
	}, nil
}

// A File represents a file that exists in an image
type File struct {
	*os.File

	layer *Layer
	path  string
}

func (f File) Open(openPath string) (lockfile.NestedDepFile, error) {
	// use path instead of filepath, because container is always in Unix paths (for now)
	if path.IsAbs(openPath) {
		return OpenLayerFile(openPath, f.layer)
	}

	absPath := path.Join(f.path, openPath)

	return OpenLayerFile(absPath, f.layer)
}

func (f File) Path() string {
	return f.path
}

func OpenLayerFile(path string, layer *Layer) (File, error) {
	fileNode, err := layer.getFileNode(path)
	if err != nil {
		return File{}, err
	}

	file, err := fileNode.Open()
	if err != nil {
		return File{}, err
	}

	return File{
		File:  file,
		path:  path,
		layer: layer,
	}, nil
}

var _ lockfile.DepFile = File{}
var _ lockfile.NestedDepFile = File{}
