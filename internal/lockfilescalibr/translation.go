package lockfilescalibr

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scanner/pkg/reporter"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// ExtractWithExtractor attempts to extract the file at the given path with the extractor passed in
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
func ExtractWithExtractors(ctx context.Context, localPath string, extractors []filesystem.Extractor, r reporter.Reporter) ([]*extractor.Inventory, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, err
	}

	result := []*extractor.Inventory{}
	extractorFound := false
	for _, ext := range extractors {
		if ext.FileRequired(localPath, info) {
			extractorFound = true

			invs, err := extractWithExtractor(ctx, localPath, info, ext)
			if err != nil {
				return nil, err
			}

			result = append(result, invs...)
		}
	}

	if !extractorFound {
		return nil, ErrExtractorNotFound
	}

	return result, nil
}

// // Extract attempts to extract the file at the given path
// //
// // Args:
// //   - localPath: the path to the lockfile
// //   - extractAs: the name of the lockfile format to extract as (Using OSV-Scanner V1 extractor names)
// //
// // Returns:
// //   - []*extractor.Inventory: the extracted lockfile data
// //   - error: any errors encountered during extraction
// //
// // If extractAs is not specified, then the function will attempt to
// // identify the lockfile format based on the file name.
// //
// // If no extractors are found, then ErrNoExtractorsFound is returned.
// func Extract(ctx context.Context, localPath string, extractAs string) ([]*extractor.Inventory, error) {
// 	info, err := os.Stat(localPath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if extractAs != "" {
// 		return extractAsSpecific(ctx, extractAs, localPath, info)
// 	}

// 	output := []*extractor.Inventory{}
// 	extractorFound := false

// 	for _, ext := range lockfileExtractors {
// 		if ext.FileRequired(localPath, info) {
// 			extractorFound = true

// 			inv, err := extractWithExtractor(ctx, localPath, info, ext)
// 			if err != nil {
// 				return nil, err
// 			}

// 			output = append(output, inv...)
// 		}
// 	}

// 	if !extractorFound {
// 		return nil, ErrNoExtractorsFound
// 	}

// 	sort.Slice(output, func(i, j int) bool {
// 		if output[i].Name == output[j].Name {
// 			return output[i].Version < output[j].Version
// 		}

// 		return output[i].Name < output[j].Name
// 	})

// 	return output, nil
// }

// // Use the extractor specified by extractAs string key
// func extractAsSpecific(ctx context.Context, extractAs string, localPath string, info fs.FileInfo) ([]*extractor.Inventory, error) {
// 	for _, ext := range lockfileExtractors {
// 		if lockfileExtractorMapping[extractAs] == ext.Name() {
// 			return extractWithExtractor(ctx, localPath, info, ext)
// 		}
// 	}

// 	return nil, fmt.Errorf("%w, requested %s", ErrExtractorNotFound, extractAs)
// }

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
