package offline

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"
)

type ZipDB struct {
	Name            string
	ArchiveURL      string
	Offline         bool
	UpdatedAt       string
	vulnerabilities []models.Vulnerability
}

// Cache stores the OSV database archive for re-use
type Cache struct {
	URL  string `json:"url"`
	ETag string `json:"etag"`
	Date string `json:"date"`
	Body []byte `json:"body"`
}

var ErrOfflineDatabaseNotFound = errors.New("no offline version of the OSV database is available")

func (db *ZipDB) cachePath() string {
	hash := sha256.Sum256([]byte(db.ArchiveURL))
	fileName := fmt.Sprintf("osv-detector-%x-db.json", hash)

	return filepath.Join(os.TempDir(), fileName)
}

func (db *ZipDB) fetchZip() ([]byte, error) {
	var cache *Cache
	cachePath := db.cachePath()

	if cacheContent, err := os.ReadFile(cachePath); err == nil {
		err := json.Unmarshal(cacheContent, &cache)

		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to parse cache from %s: %v\n", cachePath, err)
		}
	}

	if db.Offline {
		if cache == nil {
			return nil, ErrOfflineDatabaseNotFound
		}

		db.UpdatedAt = cache.Date

		return cache.Body, nil
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, db.ArchiveURL, nil)

	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	if cache != nil {
		req.Header.Add("If-None-Match", cache.ETag)
		req.Header.Add("If-Modified-Since", cache.Date)
	}

	req.Header.Set("User-Agent", osv.RequestUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		db.UpdatedAt = cache.Date

		return cache.Body, nil
	}

	var body []byte

	body, err = io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("could not read OSV database archive from response: %w", err)
	}

	etag := resp.Header.Get("ETag")
	date := resp.Header.Get("Date")

	db.UpdatedAt = date

	if etag != "" || date != "" {
		cache = &Cache{ETag: etag, Date: date, Body: body, URL: db.ArchiveURL}
	}

	cacheContents, err := json.Marshal(cache)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(cachePath, cacheContents, 0644)

		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to write cache to %s: %v\n", cachePath, err)
		}
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

func NewZippedDB(name, url string, offline bool) (*ZipDB, error) {
	db := &ZipDB{Name: name, ArchiveURL: url, Offline: offline}
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
