package localmatcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/imodels/ecosystem"
	"github.com/google/osv-scanner/v2/pkg/reporter"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var ZippedDBRemoteHost = "https://osv-vulnerabilities.storage.googleapis.com"

const envKeyLocalDBCacheDirectory = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

// LocalMatcher implements the VulnerabilityMatcher interface by downloading the osv export zip files,
// and performing the matching locally.
type LocalMatcher struct {
	dbBasePath string
	dbs        map[osvschema.Ecosystem]*ZipDB
	downloadDB bool
	// failedDBs keeps track of the errors when getting databases for each ecosystem
	failedDBs map[osvschema.Ecosystem]error
	// userAgent sets the user agent requests for db zips are made with
	userAgent string
	// TODO(v2 logging): Remove this reporter
	r reporter.Reporter

	zippedDBRemoteHost string
}

func NewLocalMatcher(r reporter.Reporter, localDBPath string, userAgent string, downloadDB bool) (*LocalMatcher, error) {
	dbBasePath, err := setupLocalDBDirectory(localDBPath)
	if err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dbBasePath, err)
	}

	return &LocalMatcher{
		dbBasePath: dbBasePath,
		dbs:        make(map[osvschema.Ecosystem]*ZipDB),
		downloadDB: downloadDB,
		r:          r,
		userAgent:  userAgent,
		failedDBs:  make(map[osvschema.Ecosystem]error),

		zippedDBRemoteHost: ZippedDBRemoteHost,
	}, nil
}

func (matcher *LocalMatcher) MatchVulnerabilities(ctx context.Context, invs []*extractor.Inventory) ([][]*osvschema.Vulnerability, error) {
	results := make([][]*osvschema.Vulnerability, 0, len(invs))

	for _, inv := range invs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkg := imodels.FromInventory(inv)
		if pkg.Ecosystem().IsEmpty() {
			if pkg.Commit() == "" {
				// This should never happen, as those results will be filtered out before matching
				return nil, errors.New("ecosystem is empty and there is no commit hash")
			}

			// Is a commit based query, skip local scanning
			results = append(results, []*osvschema.Vulnerability{})
			// TODO (V2 logging):
			matcher.r.Infof("Skipping commit scanning for: %s\n", pkg.Commit())

			continue
		}

		db, err := matcher.loadDBFromCache(ctx, pkg.Ecosystem())

		if err != nil {
			continue
		}

		results = append(results, VulnerabilitiesAffectingPackage(db.Vulnerabilities(false), pkg))
	}

	return results, nil
}

// LoadEcosystem tries to preload the ecosystem into the cache, and returns an error if the ecosystem
// cannot be loaded.
func (matcher *LocalMatcher) LoadEcosystem(ctx context.Context, ecosystem ecosystem.Parsed) (*ZipDB, error) {
	return matcher.loadDBFromCache(ctx, ecosystem)
}

func (matcher *LocalMatcher) loadDBFromCache(ctx context.Context, ecosystem ecosystem.Parsed) (*ZipDB, error) {
	if db, ok := matcher.dbs[ecosystem.Ecosystem]; ok {
		return db, nil
	}

	if matcher.failedDBs[ecosystem.Ecosystem] != nil {
		return nil, matcher.failedDBs[ecosystem.Ecosystem]
	}

	db, err := NewZippedDB(ctx, matcher.dbBasePath, string(ecosystem.Ecosystem), fmt.Sprintf("%s/%s/all.zip", matcher.zippedDBRemoteHost, ecosystem.Ecosystem), matcher.userAgent, !matcher.downloadDB)

	if err != nil {
		matcher.failedDBs[ecosystem.Ecosystem] = err
		matcher.r.Errorf("could not load db for %s ecosystem: %v\n", ecosystem.Ecosystem, err)

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
