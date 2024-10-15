package image

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/alpine/apkinstalled"
	"github.com/google/osv-scanner/pkg/lockfile"
)

// artifactExtractors contains only extractors for artifacts that are important in
// the final layer of a container image
var artifactExtractors map[string]filesystem.Extractor = map[string]filesystem.Extractor{
	// "node_modules":  lockfile.NodeModulesExtractor{},
	"apk-installed": apkinstalled.Extractor{},
	// "dpkg":          lockfile.DpkgStatusExtractor{},
	// "go-binary": lockfile.GoBinaryExtractor{},
}

func findArtifactExtractor(path string, fileInfo fs.FileInfo) []filesystem.Extractor {
	// Use ShouldExtract to collect and return a slice of artifactExtractors
	var extractors []filesystem.Extractor
	for _, extractor := range artifactExtractors {
		if extractor.FileRequired(path, fileInfo) {
			extractors = append(extractors, extractor)
		}
	}

	return extractors
}

// Note: Output is non deterministic
func extractArtifactDeps(path string, img *Image) ([]*extractor.Inventory, error) {
	pathFileInfo, err := img.LastLayer().Stat(path)
	if err != nil {
		return nil, fmt.Errorf("attempted to get FileInfo but failed: %w", err)
	}

	scalibrPath, _ := filepath.Rel("/", path)
	foundExtractors := findArtifactExtractor(scalibrPath, pathFileInfo)
	if len(foundExtractors) == 0 {
		return nil, fmt.Errorf("%w for %s", lockfile.ErrExtractorNotFound, path)
	}

	inventories := []*extractor.Inventory{}
	var extractedAs string
	for _, extractor := range foundExtractors {
		// File has to be reopened per extractor as each extractor moves the read cursor
		f, err := img.LastLayer().Open(path)
		if err != nil {
			return nil, fmt.Errorf("attempted to open file but failed: %w", err)
		}

		scanInput := &filesystem.ScanInput{
			FS:       img.LastLayer(),
			Path:     scalibrPath,
			ScanRoot: "/",
			Reader:   f,
			Info:     pathFileInfo,
		}

		newPackages, err := extractor.Extract(context.Background(), scanInput)
		f.Close()

		if err != nil {
			if errors.Is(lockfile.ErrIncompatibleFileFormat, err) {
				continue
			}

			return nil, fmt.Errorf("(extracting as %s) %w", extractor.Name(), err)
		}

		for i := range newPackages {
			newPackages[i].Extractor = extractor
		}

		extractedAs = extractor.Name()
		inventories = newPackages
		// TODO(rexpan): Determine if this it's acceptable to have multiple extractors
		// extract from the same file successfully
		break
	}

	if extractedAs == "" {
		return nil, fmt.Errorf("%w for %s", lockfile.ErrExtractorNotFound, path)
	}

	return inventories, nil
}
