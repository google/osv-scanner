// Package filter provides an annotator that filters out unscannable, non-container-relevant,
// or ignored packages from the scan results before matching begins.
package filter

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

const (
	// Name is the unique name of this annotator.
	Name = "osv-scanner/filter"
	// Version is the version of this annotator.
	Version = 0
)

// Annotator implements annotator.Annotator to filter packages.
type Annotator struct {
	mu               sync.Mutex
	configManager    *config.Manager
	isContainerScan  bool
	showAllPackages  bool
	filteredPackages []*extractor.Package
}

var _ annotator.Annotator = (*Annotator)(nil)

// NewAnnotator returns a new Annotator.
func NewAnnotator(configManager *config.Manager, isContainerScan bool, showAllPackages bool) *Annotator {
	return &Annotator{
		configManager:   configManager,
		isContainerScan: isContainerScan,
		showAllPackages: showAllPackages,
	}
}

// Name returns the unique name of the annotator.
func (a *Annotator) Name() string {
	return Name
}

// Version returns the version of the annotator.
func (a *Annotator) Version() int {
	return Version
}

// Requirements returns the requirements of this annotator.
func (a *Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Annotate filters the package list inside the inventory.
func (a *Annotator) Annotate(_ context.Context, _ *annotator.ScanInput, results *inventory.Inventory) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	packageResults := make([]*extractor.Package, 0, len(results.Packages))
	var filteredPsr []*extractor.Package

	unscannableCount := 0
	nonContainerRelevantCount := 0
	ignoredCount := 0

	for _, psr := range results.Packages {
		// 1. Filter Unscannable Packages
		isScannable := false
		switch {
		case !imodels.Ecosystem(psr).IsEmpty() && imodels.Name(psr) != "" && imodels.Version(psr) != "":
			isScannable = true
		case imodels.Commit(psr) != "":
			isScannable = true
		}

		if !isScannable {
			unscannableCount++
			if a.showAllPackages {
				filteredPsr = append(filteredPsr, psr)
			}

			continue
		}

		// Maven with name unknown or invalid ecosystem
		if (imodels.Ecosystem(psr).Ecosystem == osvconstants.EcosystemMaven && imodels.Name(psr) == "unknown") ||
			(imodels.Ecosystem(psr).GetValidity() != nil && !imodels.Ecosystem(psr).IsEmpty()) {
			unscannableCount++
			if a.showAllPackages {
				filteredPsr = append(filteredPsr, psr)
			}

			continue
		}

		// Short commit hashes warning
		if imodels.Commit(psr) != "" && len(imodels.Commit(psr)) < 40 {
			cmdlogger.Warnf("Skipping %s: short commit hash %q cannot be queried; OSV API requires a full 40-character SHA.", imodels.Name(psr), imodels.Commit(psr))
			unscannableCount++
			if a.showAllPackages {
				filteredPsr = append(filteredPsr, psr)
			}

			continue
		}

		// 2. Filter Non-Container Relevant Packages
		if a.isContainerScan && imodels.Name(psr) == "linux" {
			nonContainerRelevantCount++

			continue
		}

		// 3. Filter Ignored Packages according to config
		if a.configManager != nil {
			configToUse := a.configManager.Get(imodels.Location(psr))
			if ignore, ignoreLine := configToUse.ShouldIgnorePackage(psr); ignore {
				ignoredCount++
				pkgString := fmt.Sprintf("%s/%s/%s", imodels.Ecosystem(psr).String(), imodels.Name(psr), imodels.Version(psr))
				reason := ignoreLine.Reason
				if reason == "" {
					reason = "(no reason given)"
				}
				cmdlogger.Infof("Package %s has been filtered out because: %s", pkgString, reason)

				continue
			}
		}

		packageResults = append(packageResults, psr)
	}

	if unscannableCount > 0 {
		cmdlogger.Infof("Filtered %d local/unscannable package/s from the scan.", unscannableCount)
	}
	if nonContainerRelevantCount > 0 {
		cmdlogger.Infof("Filtered %d non container relevant package/s from the scan.", nonContainerRelevantCount)
	}
	if ignoredCount > 0 {
		cmdlogger.Infof("Filtered %d ignored package/s from the scan.", ignoredCount)
	}

	a.filteredPackages = append(a.filteredPackages, filteredPsr...)
	results.Packages = packageResults

	return nil
}

// FilteredPackages returns the list of packages filtered out that should be preserved.
func (a *Annotator) FilteredPackages() []*extractor.Package {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.filteredPackages
}
