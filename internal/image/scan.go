package image

import (
	"errors"
	"fmt"
	"io/fs"
	"log"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

// ScanImage scans an exported docker image .tar file
func ScanImage(r reporter.Reporter, imagePath string) (ScanResults, error) {
	img, err := LoadImage(imagePath)
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
		parsedLockfile, err := extractArtifactDeps(file.virtualPath, img.LastLayer())
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)
	}

	traceOrigin(img, &scannedLockfiles)

	err = img.Cleanup()
	if err != nil {
		err = fmt.Errorf("failed to cleanup: %w", img.Cleanup())
	}

	return scannedLockfiles, err
}

// traceOrigin fills out the originLayerID for each package in ScanResults
func traceOrigin(img *Image, scannedLockfiles *ScanResults) {
	// Trace package origins
	for _, file := range scannedLockfiles.Lockfiles {
		// Defined locally as this is the only place this is used.
		type PDKey struct {
			Name      string
			Version   string
			Commit    string
			Ecosystem lockfile.Ecosystem
		}

		makePDKey := func(pd lockfile.PackageDetails) PDKey {
			return PDKey{
				Name:      pd.Name,
				Version:   pd.Version,
				Commit:    pd.Commit,
				Ecosystem: pd.Ecosystem,
			}
		}

		// First get the latest file node
		lastFileNode, err := img.layers[len(img.layers)-1].getFileNode(file.FilePath)
		if err != nil {
			log.Panicf("did not expect to fail getting file node we just scanned: %v", err)
		}
		// Get the layer index this file belongs to (the last layer it was changed on)
		layerIdx := img.layerIDToIndex[lastFileNode.originLayer.id]
		var prevLayerIdx int

		sourceLayerIdx := map[PDKey]int{}
		for _, pkg := range file.Packages {
			// Start with originating from the latest layer
			// Then push back as we iterate through layers
			sourceLayerIdx[makePDKey(pkg)] = layerIdx
		}

		for {
			// Scan the lockfile again every time it was changed
			if layerIdx == 0 {
				// This layer is the base layer, we cannot go further back
				// All entries in sourceLayerIdx would have been set in the previous loop, or just above the loop
				// So we can immediately exit here
				break
			}

			// Look at the layer before the current layer
			oldFileNode, err := img.layers[layerIdx-1].getFileNode(file.FilePath)
			if errors.Is(err, fs.ErrNotExist) || (err == nil && oldFileNode.isWhiteout) {
				// Did not exist in the layer before

				// All entries in sourceLayerIdx would have been set in the previous loop, or just above the loop
				// So we can immediately exit here
				break
			}

			if err != nil {
				log.Panicf("did not expect a different error [%v] when getting file node", err)
			}

			prevLayerIdx = layerIdx
			// Set the layerIdx to the new file node layer
			layerIdx = img.layerIDToIndex[oldFileNode.originLayer.id]

			oldDeps, err := extractArtifactDeps(file.FilePath, oldFileNode.originLayer)
			if err != nil {
				// Failed to parse an older version of file in image
				// Behave as if the file does not exist
				break
				// log.Panicf("unimplemented! failed to parse an older version of file in image: %s@%s: %v", file.FilePath, oldFileNode.originLayer.id, err)
			}

			// For each package in the old version, check if it existed in the newer layer, if so, the origin must be this layer or earlier.
			for _, pkg := range oldDeps.Packages {
				key := makePDKey(pkg)
				if val, ok := sourceLayerIdx[key]; ok && val == prevLayerIdx {
					sourceLayerIdx[key] = layerIdx
				}
			}
		}

		// Finally save the package IDs back into the ScanResults
		for i, pkg := range file.Packages {
			layerID := img.layers[sourceLayerIdx[makePDKey(pkg)]].id
			// Ignore error as we can't do much about it
			originCommand, _ := img.layerIDToCommand(layerID)
			file.Packages[i].ImageOrigin = &models.ImageOriginDetails{
				LayerID:       layerID,
				OriginCommand: originCommand,
				InBaseImage:   img.layerIDToIndex[layerID] <= img.baseImageIndex,
			}
		}
	}
}
