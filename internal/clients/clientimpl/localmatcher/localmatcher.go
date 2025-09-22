// Package localmatcher implements a vulnerability matcher
// that uses a local database downloaded from osv.dev's export bucket.
package localmatcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const zippedDBRemoteHost = "https://osv-vulnerabilities.storage.googleapis.com"
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
}

func NewLocalMatcher(localDBPath string, userAgent string, downloadDB bool) (*LocalMatcher, error) {
	dbBasePath, err := setupLocalDBDirectory(localDBPath)
	if err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dbBasePath, err)
	}

	return &LocalMatcher{
		dbBasePath: dbBasePath,
		dbs:        make(map[osvschema.Ecosystem]*ZipDB),
		downloadDB: downloadDB,
		userAgent:  userAgent,
		failedDBs:  make(map[osvschema.Ecosystem]error),
	}, nil
}

func (matcher *LocalMatcher) MatchVulnerabilities(ctx context.Context, invs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	results := make([][]*osvschema.Vulnerability, 0, len(invs))

	// ensure all databases loaded so far have been fully loaded; this is just a
	// basic safeguard since we don't actually currently attempt to reuse matchers
	// across scans, and its possible we never will, so we don't need to be smart
	for _, db := range matcher.dbs {
		if db.Partial {
			return nil, errors.New("local matcher cannot be (re)used with a partially loaded database")
		}
	}

	for _, inv := range invs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkg := imodels.FromInventory(inv)
		eco := pkg.Ecosystem().Ecosystem

		if pkg.Ecosystem().IsEmpty() {
			if pkg.Commit() == "" {
				// This should never happen, as those results will be filtered out before matching
				return nil, errors.New("ecosystem is empty and there is no commit hash")
			}

			// matching ecosystem-less versions can only be attempted if we have a version
			if pkg.Version() == "" {
				// Is a commit based query, skip local scanning
				results = append(results, []*osvschema.Vulnerability{})

				// TODO (V2 logging):
				cmdlogger.Infof("Skipping commit scanning for: %s", pkg.Commit())

				continue
			}

			eco = "GIT"
		}

		db, err := matcher.loadDBFromCache(ctx, eco, invs)

		if err != nil {
			// no logging here as the loader will have already done that
			results = append(results, []*osvschema.Vulnerability{})

			continue
		}

		results = append(results, VulnerabilitiesAffectingPackage(db.Vulnerabilities, pkg))
	}

	return results, nil
}

// LoadEcosystem tries to preload the ecosystem into the cache, and returns an error if the ecosystem
// cannot be loaded.
//
// Preloaded databases include every advisory, so can be reused.
func (matcher *LocalMatcher) LoadEcosystem(ctx context.Context, eco osvecosystem.Parsed) error {
	_, err := matcher.loadDBFromCache(ctx, eco.Ecosystem, nil)

	return err
}

func (matcher *LocalMatcher) loadDBFromCache(ctx context.Context, eco osvschema.Ecosystem, invs []*extractor.Package) (*ZipDB, error) {
	if db, ok := matcher.dbs[eco]; ok {
		return db, nil
	}

	if matcher.failedDBs[eco] != nil {
		return nil, matcher.failedDBs[eco]
	}

	db, err := NewZippedDB(
		ctx,
		matcher.dbBasePath,
		string(eco),
		fmt.Sprintf("%s/%s/all.zip", zippedDBRemoteHost, eco),
		matcher.userAgent,
		!matcher.downloadDB,
		invs,
	)

	if err != nil {
		matcher.failedDBs[eco] = err
		cmdlogger.Errorf("could not load db for %s ecosystem: %v", eco, err)

		return nil, err
	}

	cmdlogger.Infof("Loaded %s local db from %s", db.Name, db.StoredAt)

	matcher.dbs[eco] = db

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
