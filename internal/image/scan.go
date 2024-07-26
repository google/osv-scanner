package image

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

// ScanImage scans an exported docker image .tar file
func ScanImage(r reporter.Reporter, imagePath string) (ScanResults, error) {
	img, err := loadImage(imagePath)
	if err != nil {
		// Ignore errors on cleanup since the folder might not have been created anyway.
		_ = img.Cleanup()
		return ScanResults{}, fmt.Errorf("failed to load image %s: %w", imagePath, err)
	}

	allFiles := img.LastLayer().AllFiles()

	scanResults := ScanResults{
		ImagePath: imagePath,
	}
	for _, file := range allFiles {
		if file.fileType != RegularFile {
			continue
		}
		extractedInventories, err := extractArtifactDeps(file.virtualPath, &img)
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}

		scanResults.Inventories = append(scanResults.Inventories, extractedInventories...)
	}

	// Sort to have deterministic output, and to match behavior of lockfile.extractDeps
	slices.SortFunc(scanResults.Inventories, func(a, b *lockfilescalibr.Inventory) int {
		// TODO: Should we consider errors here?
		aPURL, _ := a.Extractor.ToPURL(a)
		bPURL, _ := b.Extractor.ToPURL(b)

		return strings.Compare(aPURL.ToString(), bPURL.ToString())
	})

	err = img.Cleanup()
	if err != nil {
		err = fmt.Errorf("failed to cleanup: %w", img.Cleanup())
	}

	return scanResults, err
}
