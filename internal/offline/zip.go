package offline

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type ZipDB struct {
	Name            string
	ArchiveURL      string
	Offline         bool
	StoredAt        string
	vulnerabilities []models.Vulnerability
}

var ErrOfflineDatabaseNotFound = errors.New("no offline version of the OSV database is available")

func (db *ZipDB) fetchZip() ([]byte, error) {
	if db.Offline {
		cache, err := os.ReadFile(db.StoredAt)

		if err != nil {
			return nil, ErrOfflineDatabaseNotFound
		}

		return cache, nil
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, db.ArchiveURL, nil)

	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	req.Header.Set("User-Agent", osv.RequestUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	defer resp.Body.Close()

	var body []byte

	body, err = io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("could not read OSV database archive from response: %w", err)
	}

	err = os.MkdirAll(path.Dir(db.StoredAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(db.StoredAt, body, 0644)
	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to save database to %s: %v\n", db.StoredAt, err)
	}

	return body, nil
}

// Loads the given zip file into the database as an OSV.
// It is assumed that the file is JSON and in the working directory of the db
func (db *ZipDB) loadZipFile(zipFile *zip.File) {
	file, err := zipFile.Open()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", zipFile.Name, err)

		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not read %s: %v\n", zipFile.Name, err)

		return
	}

	var vulnerability models.Vulnerability

	if err := json.Unmarshal(content, &vulnerability); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s is not a valid JSON file: %v\n", zipFile.Name, err)

		return
	}

	db.vulnerabilities = append(db.vulnerabilities, vulnerability)
}

// load fetches a zip archive of the OSV database and loads known vulnerabilities
// from it (which are assumed to be in json files following the OSV spec).
//
// Internally, the archive is cached along with the date that it was fetched
// so that a new version of the archive is only downloaded if it has been
// modified, per HTTP caching standards.
func (db *ZipDB) load() error {
	db.vulnerabilities = []models.Vulnerability{}

	body, err := db.fetchZip()

	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("could not read OSV database archive: %w", err)
	}

	// Read all the files from the zip archive
	for _, zipFile := range zipReader.File {
		if !strings.HasSuffix(zipFile.Name, ".json") {
			continue
		}

		db.loadZipFile(zipFile)
	}

	return nil
}

func NewZippedDB(dbBasePath, name, url string, offline bool) (*ZipDB, error) {
	db := &ZipDB{
		Name:       name,
		ArchiveURL: url,
		Offline:    offline,
		StoredAt:   path.Join(dbBasePath, name, "all.zip"),
	}
	if err := db.load(); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

func (db *ZipDB) Vulnerabilities(includeWithdrawn bool) []models.Vulnerability {
	if includeWithdrawn {
		return db.vulnerabilities
	}

	var vulnerabilities []models.Vulnerability

	for _, vulnerability := range db.vulnerabilities {
		if vulnerability.Withdrawn.IsZero() {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func (db *ZipDB) VulnerabilitiesAffectingPackage(pkg lockfile.PackageDetails) models.Vulnerabilities {
	var vulnerabilities models.Vulnerabilities

	for _, vulnerability := range db.Vulnerabilities(false) {
		if vulnerability.IsAffected(pkg) && !vulnerabilities.Includes(vulnerability) {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func (db *ZipDB) Check(pkgs []lockfile.PackageDetails) (models.Vulnerabilities, error) {
	vulnerabilities := make(models.Vulnerabilities, 0, len(pkgs))

	for _, pkg := range pkgs {
		vulnerabilities = append(vulnerabilities, db.VulnerabilitiesAffectingPackage(pkg)...)
	}

	return vulnerabilities, nil
}
