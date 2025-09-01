// Package scalibrextract provides functions to easily use scalibr extractors within osv-scanner.
package scalibrextract

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/plugin"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// ExtractWithExtractor attempts to extract the file at the given path with the extractor passed in
//
// # Extract attempts to extract the file at the given path
//
// Args:
//   - ctx: the context to use for extraction
//   - localPath: the path to the lockfile
//   - ext: the extractor to use
//
// Returns:
//   - []*extractor.Package: the extracted lockfile data
//   - error: any errors encountered during extraction
func ExtractWithExtractor(ctx context.Context, localPath string, ext filesystem.Extractor) ([]*extractor.Package, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	return extractWithExtractor(ctx, localPath, info, ext)
}

// ExtractWithExtractors attempts to extract the file at the given path
// by choosing the extractor which passes the FileRequired test
// TODO: Optimise to pass in FileInfo here.
// TODO: Remove reporter
//
// Args:
// - ctx: the context to use for extraction
// - localPath: the path to the lockfile
// - extractors: a slice of extractors to try
// - r: reporter to output logs to
//
// Returns:
//   - []*extractor.Package: the extracted lockfile data
//   - error: any errors encountered during extraction
//
// If no extractors are found, then ErrExtractorNotFound is returned.
func ExtractWithExtractors(ctx context.Context, localPath string, plugins []plugin.Plugin) ([]*extractor.Package, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	result := []*extractor.Package{}
	extractorFound := false
	for _, plug := range plugins {
		ext, ok := plug.(filesystem.Extractor)

		if !ok || !ext.FileRequired(simplefileapi.New(localPath, info)) {
			continue
		}
		extractorFound = true

		invs, err := extractWithExtractor(ctx, localPath, info, ext)
		if err != nil {
			return nil, err
		}

		result = append(result, invs...)
	}

	if !extractorFound {
		return nil, ErrExtractorNotFound
	}

	return result, nil
}

func extractWithExtractor(ctx context.Context, localPath string, info fs.FileInfo, ext filesystem.Extractor) ([]*extractor.Package, error) {
	// Create a scan input centered at the system root directory,
	// to give access to the full filesystem for each extractor.
	rootDir := getRootDir(localPath)
	si, err := createScanInput(localPath, rootDir, info)
	if err != nil {
		return nil, err
	}

	invs, err := ext.Extract(ctx, si)
	if err != nil {
		return nil, fmt.Errorf("(extracting as %s) %w", ext.Name(), err)
	}

	for i := range invs.Packages {
		// Set parent extractor
		invs.Packages[i].Plugins = append(invs.Packages[i].Plugins, ext.Name())

		// Make Location relative to the scan root as we are performing local scanning
		for i2 := range invs.Packages[i].Locations {
			invs.Packages[i].Locations[i2] = filepath.Join(rootDir, invs.Packages[i].Locations[i2])
		}
	}

	slices.SortFunc(invs.Packages, inventorySort)
	invsCompact := slices.CompactFunc(invs.Packages, func(a, b *extractor.Package) bool {
		return inventorySort(a, b) == 0
	})

	return invsCompact, nil
}

func createScanInput(path string, root string, fileInfo fs.FileInfo) (*filesystem.ScanInput, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Rel will strip root from the input path.
	path, err = filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}

	// Convert path to slashes, as go FS expects unix like paths
	path = filepath.ToSlash(path)

	si := filesystem.ScanInput{
		FS:     os.DirFS(root).(scalibrfs.FS),
		Path:   path,
		Root:   root,
		Reader: reader,
		Info:   fileInfo,
	}

	return &si, nil
}

// getRootDir returns the root directory on each system.
// On Unix systems, it'll be /
// On Windows, it will most likely be the drive (e.g. C:\)
func getRootDir(path string) string {
	if runtime.GOOS == "windows" {
		return filepath.VolumeName(path) + "\\"
	}

	if strings.HasPrefix(path, "/") {
		return "/"
	}

	return ""
}
