package scanners

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

// ScanSBOMFile will load, identify, and parse the SBOM path passed in, and add the dependencies specified
// within to `query`
func ScanSBOMFile(r reporter.Reporter, path string, fromFSScan bool) ([]imodels.ScannedPackage, error) {
	var errs []error
	packages := map[string]imodels.ScannedPackage{}
	for _, provider := range sbom.Providers {
		if fromFSScan && !provider.MatchesRecognizedFileNames(path) {
			// Skip if filename is not usually a sbom file of this format.
			// Only do this if this is being done in a filesystem scanning context, where we need to be
			// careful about spending too much time attempting to parse unrelated files.
			// If this is coming from an explicit scan argument, be more relaxed here since it's common for
			// filenames to not conform to expected filename standards.
			continue
		}

		// Opening file inside loop is OK, since providers is not very long,
		// and it is unlikely that multiple providers accept the same file name
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		var ignoredPURLs []string
		err = provider.GetPackages(file, func(id sbom.Identifier) error {
			_, err := models.PURLToPackage(id.PURL)
			if err != nil {
				ignoredPURLs = append(ignoredPURLs, id.PURL)
				//nolint:nilerr
				return nil
			}

			if _, ok := packages[id.PURL]; ok {
				r.Warnf("Warning, duplicate PURL found in SBOM: %s\n", id.PURL)
			}

			packages[id.PURL] = imodels.ScannedPackage{
				PURL: id.PURL,
				Source: models.SourceInfo{
					Path: path,
					Type: "sbom",
				},
			}

			return nil
		})
		if err == nil {
			// Found a parsable format.
			if len(packages) == 0 {
				// But no entries found, so maybe not the correct format
				errs = append(errs, sbom.InvalidFormatError{
					Msg: "no Package URLs found",
					Errs: []error{
						fmt.Errorf("scanned %s as %s SBOM, but failed to find any package URLs, this is required to scan SBOMs", path, provider.Name()),
					},
				})

				continue
			}
			r.Infof(
				"Scanned %s as %s SBOM and found %d %s\n",
				path,
				provider.Name(),
				len(packages),
				output.Form(len(packages), "package", "packages"),
			)
			if len(ignoredPURLs) > 0 {
				r.Warnf(
					"Ignored %d %s with invalid PURLs\n",
					len(ignoredPURLs),
					output.Form(len(ignoredPURLs), "package", "packages"),
				)
				slices.Sort(ignoredPURLs)
				for _, purl := range slices.Compact(ignoredPURLs) {
					r.Warnf(
						"Ignored invalid PURL \"%s\"\n",
						purl,
					)
				}
			}

			sliceOfPackages := make([]imodels.ScannedPackage, 0, len(packages))

			for _, pkg := range packages {
				sliceOfPackages = append(sliceOfPackages, pkg)
			}

			slices.SortFunc(sliceOfPackages, func(i, j imodels.ScannedPackage) int {
				return strings.Compare(i.PURL, j.PURL)
			})

			return sliceOfPackages, nil
		}

		var formatErr sbom.InvalidFormatError
		if errors.As(err, &formatErr) {
			errs = append(errs, err)
			continue
		}

		return nil, err
	}

	// Don't log these errors if we're coming from an FS scan, since it can get very noisy.
	if !fromFSScan {
		r.Infof("Failed to parse SBOM using all supported formats:\n")
		for _, err := range errs {
			r.Infof("%s\n", err.Error())
		}
	}

	return nil, nil
}
