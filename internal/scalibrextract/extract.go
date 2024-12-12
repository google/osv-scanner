package scalibrextract

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"

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
//   - []*extractor.Inventory: the extracted lockfile data
//   - error: any errors encountered during extraction
func ExtractWithExtractor(ctx context.Context, localPath string, ext filesystem.Extractor) ([]*extractor.Inventory, error) {
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
//   - []*extractor.Inventory: the extracted lockfile data
//   - error: any errors encountered during extraction
//
// If no extractors are found, then ErrExtractorNotFound is returned.
func ExtractWithExtractors(ctx context.Context, localPath string, extractors []filesystem.Extractor) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	result := []*extractor.Inventory{}
	extractorFound := false
	for _, ext := range extractors {
		if !ext.FileRequired(localPath, info) {
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

func extractWithExtractor(ctx context.Context, localPath string, info fs.FileInfo, ext filesystem.Extractor) ([]*extractor.Inventory, error) {
	si, err := createScanInput(localPath, info)
	if err != nil {
		return nil, err
	}

	invs, err := ext.Extract(ctx, si)
	if err != nil {
		return nil, fmt.Errorf("(extracting as %s) %w", ext.Name(), err)
	}

	for i := range invs {
		invs[i].Extractor = ext
	}

	slices.SortFunc(invs, inventorySort)
	invsCompact := slices.CompactFunc(invs, func(a, b *extractor.Inventory) bool {
		return inventorySort(a, b) == 0
	})

	return invsCompact, nil
}

func createScanInput(path string, fileInfo fs.FileInfo) (*filesystem.ScanInput, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	si := filesystem.ScanInput{
		FS:     os.DirFS("/").(scalibrfs.FS),
		Path:   path,
		Root:   "/",
		Reader: reader,
		Info:   fileInfo,
	}

	return &si, nil
}
