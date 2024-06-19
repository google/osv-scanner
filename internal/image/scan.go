package image

import (
	"errors"
	"fmt"
	"io/fs"
	"log"

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

		parsedLockfile, err := extractArtifactDeps(file.virtualPath, img.LastLayer())
		if err != nil {
			if !errors.Is(err, lockfile.ErrExtractorNotFound) {
				r.Errorf("Attempted to extract lockfile but failed: %s - %v\n", file.virtualPath, err)
			}

			continue
		}

		// Trace package origins
		for _, file := range scannedLockfiles.Lockfiles {
			// Defined locally as this is the only place this is used.
			type PDKey struct {
				Name      string
				Version   string
				Commit    string
				Ecosystem lockfile.Ecosystem
			}

			makePdKey := func(pd lockfile.PackageDetails) PDKey {
				return PDKey{
					Name:      pd.Name,
					Version:   pd.Version,
					Commit:    pd.Commit,
					Ecosystem: pd.Ecosystem,
				}
			}

			sourceLayerIdx := map[PDKey]int{}
			for _, pkg := range file.Packages {
				sourceLayerIdx[makePdKey(pkg)] = 0
			}

			// First get the latest file node
			lastFileNode, err := img.layers[len(img.layers)-1].GetFileNode(file.FilePath)
			if err != nil {
				log.Panicf("did not expect to fail getting file node we just scanned: %v", err)
			}
			// Get the layer index this file belongs to (the last layer it was changed on)
			layerIdx := img.layerIdToIndex[lastFileNode.layer.id]
			for {
				// Scan the lockfile again every time it was changed
				if layerIdx == 0 {
					// This layer is the base layer, this is the originating layer for all remaining packages
					// Since the default value in sourceLayerIdx is 0, no changes need to be made here
					break
				}
				// Look at the layer before the current layer
				oldFileNode, err := img.layers[layerIdx-1].GetFileNode(file.FilePath)
				if err != nil {
					if err == fs.ErrNotExist { // Did not exist in the layer before, all remaining packages must be from the current layer
						for key, val := range sourceLayerIdx {
							if val == 0 {
								sourceLayerIdx[key] = layerIdx
							}
						}
						break
					}
					log.Panicf("did not expect a different error [%v] when getting file node", err)
				}

				// Set the layerIdx to the new file node layer
				layerIdx = img.layerIdToIndex[oldFileNode.layer.id]

				oldDeps, err := extractArtifactDeps(file.FilePath, *oldFileNode.layer)
				if err != nil {
					// TODO: What to do here?
				}

				for _, pkg := range oldDeps.Packages {
					key := makePdKey(pkg)
					if val, ok := sourceLayerIdx[key]; ok && val == 0 {
						sourceLayerIdx[key] = layerIdx
					}
				}
				// TODO: Add check here to shortcut if all packages have been accounted for
			}

			for i, pkg := range file.Packages {
				file.Packages[i].OriginLayerId = img.layers[sourceLayerIdx[makePdKey(pkg)]].id
			}
		}

		scannedLockfiles.Lockfiles = append(scannedLockfiles.Lockfiles, parsedLockfile)
	}

	err = img.Cleanup()
	if err != nil {
		err = fmt.Errorf("failed to cleanup: %w", img.Cleanup())
	}

	return scannedLockfiles, err
}
