package image

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/nodemodules"
	"github.com/google/osv-scanner/pkg/lockfile"
)

// artifactExtractors contains only extractors for artifacts that are important in
// the final layer of a container image
var artifactExtractors []filesystem.Extractor = []filesystem.Extractor{
	// TODO: Using nodemodules extractor to minimize changes of snapshots
	// After annotations are added, we should switch to using packagejson.
	// packagejson.New(packagejson.DefaultConfig()),
	nodemodules.Extractor{},

	apk.New(apk.DefaultConfig()),
	gobinary.New(gobinary.DefaultConfig()),
	// TODO: Add tests for debian containers
	dpkg.New(dpkg.DefaultConfig()),
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
func extractArtifactDeps(extractPath string, layer *Layer) ([]*extractor.Inventory, error) {
	pathFileInfo, err := layer.Stat(extractPath)
	if err != nil {
		return nil, fmt.Errorf("attempted to get FileInfo but failed: %w", err)
	}

	scalibrPath := strings.TrimPrefix(extractPath, "/")
	foundExtractors := findArtifactExtractor(scalibrPath, pathFileInfo)
	if len(foundExtractors) == 0 {
		return nil, fmt.Errorf("%w for %s", lockfilescalibr.ErrExtractorNotFound, extractPath)
	}

	inventories := []*extractor.Inventory{}
	var extractedAs string
	for _, extractor := range foundExtractors {
		// File has to be reopened per extractor as each extractor moves the read cursor
		f, err := layer.Open(extractPath)
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
			if errors.Is(err, lockfile.ErrIncompatibleFileFormat) {
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
		return nil, fmt.Errorf("%w for %s", lockfilescalibr.ErrExtractorNotFound, extractPath)
	}

	// Perform any one-off translations here
	for _, inv := range inventories {
		// Scalibr uses go to indicate go compiler version
		// We specifically cares about the stdlib version inside the package
		// so convert the package name from go to stdlib
		if inv.Ecosystem() == "Go" && inv.Name == "go" {
			inv.Name = "stdlib"
		}
	}

	return inventories, nil
}
