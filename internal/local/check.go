package local

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"
)

const zippedDBRemoteHost = "https://osv-vulnerabilities.storage.googleapis.com"
const envKeyLocalDBCacheDirectory = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

func loadDB(dbBasePath string, ecosystem lockfile.Ecosystem, offline bool) (*ZipDB, error) {
	return NewZippedDB(dbBasePath, string(ecosystem), fmt.Sprintf("%s/%s/all.zip", zippedDBRemoteHost, ecosystem), offline)
}

func toPackageDetails(query *osv.Query) (lockfile.PackageDetails, error) {
	if query.Package.PURL != "" {
		pkg, err := models.PURLToPackage(query.Package.PURL)

		if err != nil {
			return lockfile.PackageDetails{}, err
		}

		return lockfile.PackageDetails{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: lockfile.Ecosystem(pkg.Ecosystem),
			CompareAs: lockfile.Ecosystem(pkg.Ecosystem),
		}, nil
	}

	return lockfile.PackageDetails{
		Name:      query.Package.Name,
		Version:   query.Version,
		Commit:    query.Commit,
		Ecosystem: lockfile.Ecosystem(query.Package.Ecosystem),
		CompareAs: lockfile.Ecosystem(query.Package.Ecosystem),
	}, nil
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

func MakeRequest(r reporter.Reporter, query osv.BatchedQuery, offline bool, localDBPath string) (*osv.HydratedBatchedResponse, error) {
	results := make([]osv.Response, 0, len(query.Queries))
	dbs := make(map[lockfile.Ecosystem]*ZipDB)

	dbBasePath, err := setupLocalDBDirectory(localDBPath)

	if err != nil {
		return &osv.HydratedBatchedResponse{}, fmt.Errorf("could not create %s: %w", dbBasePath, err)
	}

	loadDBFromCache := func(ecosystem lockfile.Ecosystem) (*ZipDB, error) {
		if db, ok := dbs[ecosystem]; ok {
			return db, nil
		}

		db, err := loadDB(dbBasePath, ecosystem, offline)

		if err != nil {
			return nil, err
		}

		r.Infof("Loaded %s local db from %s\n", db.Name, db.StoredAt)

		dbs[ecosystem] = db

		return db, nil
	}

	// slice to track ecosystems that did not have an offline database available
	var missingDbs []string

	for _, query := range query.Queries {
		pkg, err := toPackageDetails(query)

		if err != nil {
			// currently, this will actually only error if the PURL cannot be parses
			r.Errorf("skipping %s as it is not a valid PURL: %v\n", query.Package.PURL, err)
			results = append(results, osv.Response{Vulns: []models.Vulnerability{}})

			continue
		}

		if pkg.Ecosystem == "" {
			if pkg.Commit == "" {
				// The only time this can happen should be when someone passes in their own OSV-Scanner-Results file.
				return nil, errors.New("ecosystem is empty and there is no commit hash")
			}

			// Is a commit based query, skip local scanning
			results = append(results, osv.Response{})
			r.Infof("Skipping commit scanning for: %s\n", pkg.Commit)

			continue
		}

		db, err := loadDBFromCache(pkg.Ecosystem)

		if err != nil {
			if errors.Is(err, ErrOfflineDatabaseNotFound) {
				missingDbs = append(missingDbs, string(pkg.Ecosystem))
			} else {
				// the most likely error at this point is that the PURL could not be parsed
				r.Errorf("could not load db for %s ecosystem: %v\n", pkg.Ecosystem, err)
			}

			results = append(results, osv.Response{Vulns: []models.Vulnerability{}})

			continue
		}

		results = append(results, osv.Response{Vulns: db.VulnerabilitiesAffectingPackage(pkg)})
	}

	if len(missingDbs) > 0 {
		missingDbs = slices.Compact(missingDbs)
		slices.Sort(missingDbs)

		r.Errorf("could not find local databases for ecosystems: %s\n", strings.Join(missingDbs, ", "))
	}

	return &osv.HydratedBatchedResponse{Results: results}, nil
}
