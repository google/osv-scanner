package image

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/pkg/lockfile"
)

// artifactExtractors contains only extractors for artifacts that are important in
// the final layer of a container image
var artifactExtractors map[string]filesystem.Extractor = map[string]filesystem.Extractor{
	"packagejson":   packagejson.New(packagejson.DefaultConfig()),
	"apk-installed": apk.New(apk.DefaultConfig()),
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
func extractArtifactDeps(path string, layer *Layer) ([]*extractor.Inventory, error) {
	pathFileInfo, err := layer.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("attempted to get FileInfo but failed: %w", err)
	}

	scalibrPath, _ := filepath.Rel("/", path)
	foundExtractors := findArtifactExtractor(scalibrPath, pathFileInfo)
	if len(foundExtractors) == 0 {
		return nil, fmt.Errorf("%w for %s", lockfilescalibr.ErrExtractorNotFound, path)
	}

	inventories := []*extractor.Inventory{}
	var extractedAs string
	for _, extractor := range foundExtractors {
		// File has to be reopened per extractor as each extractor moves the read cursor
		f, err := layer.Open(path)
		if err != nil {
			return nil, fmt.Errorf("attempted to open file but failed: %w", err)
		}

		scanInput := &filesystem.ScanInput{
			FS:     layer,
			Path:   scalibrPath,
			Root:   "/",
			Reader: f,
			Info:   pathFileInfo,
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
		return nil, fmt.Errorf("%w for %s", lockfilescalibr.ErrExtractorNotFound, path)
	}

	return inventories, nil
}
