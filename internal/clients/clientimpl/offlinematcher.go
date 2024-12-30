package clientimpl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/internal/imodels"
	"github.com/google/osv-scanner/internal/imodels/ecosystem"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const zippedDBRemoteHost = "https://osv-vulnerabilities.storage.googleapis.com"
const envKeyLocalDBCacheDirectory = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

type OfflineMatcher struct {
	dbBasePath  string
	dbs         map[osvschema.Ecosystem]*ZipDB
	offlineMode bool
	// TODO(v2 logging): Remove this reporter
	r reporter.Reporter
}

func NewOfflineMatcher(r reporter.Reporter, localDBPath string, offlineMode bool) (*OfflineMatcher, error) {
	dbBasePath, err := setupLocalDBDirectory(localDBPath)
	if err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dbBasePath, err)
	}

	return &OfflineMatcher{
		dbBasePath:  dbBasePath,
		dbs:         make(map[osvschema.Ecosystem]*ZipDB),
		offlineMode: offlineMode,
		r:           r,
	}, nil
}

func (matcher *OfflineMatcher) Match(ctx context.Context, invs []*extractor.Inventory) ([][]*models.Vulnerability, error) {
	results := make([][]*models.Vulnerability, 0, len(invs))

	// slice to track ecosystems that did not have an offline database available
	var missingDbs []string

	for _, inv := range invs {
		pkg := imodels.FromInventory(inv)
		if pkg.Ecosystem.IsEmpty() {
			if pkg.Commit == "" {
				// This should never happen, as those results will be filtered out before matching
				return nil, errors.New("ecosystem is empty and there is no commit hash")
			}

			// Is a commit based query, skip local scanning
			results = append(results, []*models.Vulnerability{})
			// TODO (V2 logging):
			matcher.r.Infof("Skipping commit scanning for: %s\n", pkg.Commit)

			continue
		}

		db, err := matcher.loadDBFromCache(pkg.Ecosystem)

		if err != nil {
			if errors.Is(err, ErrOfflineDatabaseNotFound) {
				missingDbs = append(missingDbs, string(pkg.Ecosystem.Ecosystem))
			} else {
				// TODO(V2 logging):
				// the most likely error at this point is that the PURL could not be parsed
				matcher.r.Errorf("could not load db for %s ecosystem: %v\n", pkg.Ecosystem, err)
			}

			results = append(results, []*models.Vulnerability{})

			continue
		}

		results = append(results, db.VulnerabilitiesAffectingPackage(pkg))
	}

	if len(missingDbs) > 0 {
		missingDbs = slices.Compact(missingDbs)
		slices.Sort(missingDbs)

		// TODO(v2 logging):
		matcher.r.Errorf("could not find local databases for ecosystems: %s\n", strings.Join(missingDbs, ", "))
	}

	return results, nil
}

func (matcher *OfflineMatcher) loadDBFromCache(ecosystem ecosystem.Parsed) (*ZipDB, error) {
	if db, ok := matcher.dbs[ecosystem.Ecosystem]; ok {
		return db, nil
	}

	db, err := NewZippedDB(matcher.dbBasePath, string(ecosystem.Ecosystem), fmt.Sprintf("%s/%s/all.zip", zippedDBRemoteHost, ecosystem.Ecosystem), matcher.offlineMode)

	if err != nil {
		return nil, err
	}

	// TODO(v2 logging): Replace with slog / another logger
	matcher.r.Infof("Loaded %s local db from %s\n", db.Name, db.StoredAt)

	matcher.dbs[ecosystem.Ecosystem] = db

	return db, nil
}

// setupLocalDBDirectory attempts to set up the directory the scanner should
// use to store local databases.
//
// if a local path is explicitly provided either by the localDBPath parameter
// or via the envKeyLocalDBCacheDirectory environment variable, the scanner will
// attempt to use the user cache directory if possible or otherwise the temp directory
//
// if an error occurs at any point when a local path is not explicitly provided,
// the scanner will fall back to the temp directory first before finally erroring
func setupLocalDBDirectory(localDBPath string) (string, error) {
	var err error

	// fallback to the env variable if a local database path has not been provided
	if localDBPath == "" {
		if p, envSet := os.LookupEnv(envKeyLocalDBCacheDirectory); envSet {
			localDBPath = p
		}
	}

	implicitPath := localDBPath == ""

	// if we're implicitly picking a path, use the user cache directory if available
	if implicitPath {
		localDBPath, err = os.UserCacheDir()

		if err != nil {
			localDBPath = os.TempDir()
		}
	}

	altPath := path.Join(localDBPath, "osv-scanner")
	err = os.MkdirAll(altPath, 0750)
	if err == nil {
		return altPath, nil
	}

	// if we're implicitly picking a path, try the temp directory before giving up
	if implicitPath && localDBPath != os.TempDir() {
		return setupLocalDBDirectory(os.TempDir())
	}

	return "", err
}
