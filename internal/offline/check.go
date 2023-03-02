package offline

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
	"github.com/google/osv-scanner/pkg/reporter"
)

func loadDB(ecosystem lockfile.Ecosystem, offline bool) (*ZipDB, error) {
	return NewZippedDB(string(ecosystem), fmt.Sprintf("https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip", ecosystem), offline)
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
		Ecosystem: query.Package.Ecosystem,
		CompareAs: query.Package.Ecosystem,
	}, nil
}

func Check(r reporter.Reporter, query osv.BatchedQuery, offline bool) (*osv.HydratedBatchedResponse, error) {
	results := make([]osv.Response, 0, len(query.Queries))
	dbs := make(map[lockfile.Ecosystem]*ZipDB)

	loadDBFromCache := func(ecosystem lockfile.Ecosystem) (*ZipDB, error) {
		if db, ok := dbs[ecosystem]; ok {
			return db, nil
		}

		db, err := loadDB(ecosystem, offline)

		if err != nil {
			return nil, err
		}

		dbs[ecosystem] = db

		return db, nil
	}

	for _, query := range query.Queries {
		pkg, err := toPackageDetails(query)

		if err != nil {
			// currently, this will actually only error if the PURL cannot be parses
			r.PrintError(fmt.Sprintf("skipping %s as it is not a valid PURL: %v\n", query.Package.PURL, err))
			results = append(results, osv.Response{Vulns: []models.Vulnerability{}})

			continue
		}

		db, err := loadDBFromCache(pkg.Ecosystem)

		if err != nil {
			// currently, this will actually only error if the PURL cannot be parses
			r.PrintError(fmt.Sprintf("could not load db for %s ecosystem: %v\n", pkg.Ecosystem, err))
			results = append(results, osv.Response{Vulns: []models.Vulnerability{}})

			continue
		}

		results = append(results, osv.Response{Vulns: db.VulnerabilitiesAffectingPackage(pkg)})
	}

	return &osv.HydratedBatchedResponse{Results: results}, nil
}
