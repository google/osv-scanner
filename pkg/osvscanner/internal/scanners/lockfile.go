package scanners

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	scalibrosv "github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

// ScanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
//
// TODO(V2 Models): pomExtractor is temporary until V2 Models
func ScanLockfile(r reporter.Reporter, path string, parseAs string, pomExtractor filesystem.Extractor) ([]imodels.ScannedPackage, error) {
	var err error

	var inventories []*extractor.Inventory

	// special case for the APK and DPKG parsers because they have a very generic name while
	// living at a specific location, so they are not included in the map of parsers
	// used by lockfile.Parse to avoid false-positives when scanning projects
	switch parseAs {
	case "apk-installed":
		inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, apk.New(apk.DefaultConfig()))
	case "dpkg-status":
		inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, dpkg.New(dpkg.DefaultConfig()))
	case "osv-scanner":
		inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, osvscannerjson.Extractor{})
	default:
		if pomExtractor != nil && (parseAs == "pom.xml" || filepath.Base(path) == "pom.xml") {
			inventories, err = lockfilescalibr.ExtractWithExtractor(context.Background(), path, pomExtractor)
		} else {
			inventories, err = lockfilescalibr.Extract(context.Background(), path, parseAs)
		}
	}

	if err != nil {
		return nil, err
	}

	parsedAsComment := ""

	if parseAs != "" {
		parsedAsComment = fmt.Sprintf("as a %s ", parseAs)
	}

	slices.SortFunc(inventories, func(i, j *extractor.Inventory) int {
		return cmp.Or(
			strings.Compare(i.Name, j.Name),
			strings.Compare(i.Version, j.Version),
		)
	})

	pkgCount := len(inventories)

	r.Infof(
		"Scanned %s file %sand found %d %s\n",
		path,
		parsedAsComment,
		pkgCount,
		output.Form(pkgCount, "package", "packages"),
	)

	packages := make([]imodels.ScannedPackage, 0, pkgCount)

	for _, inv := range inventories {
		scannedPackage := imodels.ScannedPackage{
			Name:    inv.Name,
			Version: inv.Version,
			Source: models.SourceInfo{
				Path: path,
				Type: "lockfile",
			},
		}
		if inv.SourceCode != nil {
			scannedPackage.Commit = inv.SourceCode.Commit
		}
		eco := inv.Ecosystem()
		// TODO(rexpan): Refactor these minor patches to individual items
		// TODO: Ecosystem should be pared with Enum : Suffix
		if eco == "Alpine" {
			eco = "Alpine:v3.20"
		}

		scannedPackage.Ecosystem = lockfile.Ecosystem(eco)

		if dg, ok := inv.Metadata.(scalibrosv.DepGroups); ok {
			scannedPackage.DepGroups = dg.DepGroups()
		}

		packages = append(packages, scannedPackage)
	}

	return packages, nil
}
