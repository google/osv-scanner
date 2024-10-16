package image

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"golang.org/x/exp/maps"
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

	scanResults := ScanResults{
		ImagePath: imagePath,
	}

	inventories := []*extractor.Inventory{}

	for _, file := range allFiles {
		if file.fileType != RegularFile {
			continue
		}
		extractedInventories, err := extractArtifactDeps(file.virtualPath, img.LastLayer())
		if err != nil {
			if !errors.Is(err, lockfilescalibr.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}
		// scanResults.Lz
		inventories = append(inventories, extractedInventories...)
	}

	lockfiles := map[string]lockfile.Lockfile{}
	for _, i := range inventories {
		lf, exists := lockfiles[i.Locations[0]]
		if !exists {
			lf = lockfile.Lockfile{
				FilePath: i.Locations[0],
				ParsedAs: i.Extractor.Name(),
			}
		}

		pkg := lockfile.PackageDetails{
			Name:      i.Name,
			Version:   i.Version,
			Ecosystem: lockfile.Ecosystem(i.Ecosystem()),
			CompareAs: lockfile.Ecosystem(i.Ecosystem()),
		}
		if i.SourceCode != nil {
			pkg.Commit = i.SourceCode.Commit
		}

		lf.Packages = append(lf.Packages, pkg)

		lockfiles[i.Locations[0]] = lf
	}

	traceOrigin(img, &scanResults)
	scanResults.Lockfiles = maps.Values(lockfiles)
	slices.SortFunc(scanResults.Lockfiles, func(a, b lockfile.Lockfile) int {
		return strings.Compare(a.FilePath, b.FilePath)
	})

	// Sort to have deterministic output, and to match behavior of lockfile.extractDeps
	// slices.SortFunc(scanResults.Inventories, func(a, b *extractor.Inventory) int {
	// 	// TODO: Should we consider errors here?
	// 	aPURL, _ := a.Extractor.ToPURL(a)
	// 	bPURL, _ := b.Extractor.ToPURL(b)

	// 	return strings.Compare(aPURL.ToString(), bPURL.ToString())
	// })

	err = img.Cleanup()
	if err != nil {
		err = fmt.Errorf("failed to cleanup: %w", img.Cleanup())
	}

	return scanResults, err
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
			Ecosystem string
		}

		makePDKey := func(pd lockfile.PackageDetails) PDKey {
			return PDKey{
				Name:      pd.Name,
				Version:   pd.Version,
				Commit:    pd.Commit,
				Ecosystem: string(pd.Ecosystem),
			}
		}

		makePDKey2 := func(pd *extractor.Inventory) PDKey {
			return PDKey{
				Name:      pd.Name,
				Version:   pd.Version,
				Ecosystem: pd.Ecosystem(),
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
			for _, pkg := range oldDeps {
				key := makePDKey2(pkg)
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
