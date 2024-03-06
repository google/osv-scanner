package image

import (
	"errors"
	"fmt"

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

	scannedLockfiles := ScanResults{
		ImagePath: imagePath,
	}
	for _, file := range allFiles {
		if file.fileType != RegularFile {
			continue
		}

		parsedLockfile, err := extractArtifactDeps(file.virtualPath, &img)
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)
	}

	err = img.Cleanup()
	if err != nil {
		err = fmt.Errorf("failed to cleanup: %w", img.Cleanup())
	}

	return scannedLockfiles, err
}
