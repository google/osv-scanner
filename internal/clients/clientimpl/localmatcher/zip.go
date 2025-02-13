package localmatcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/utility/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type ZipDB struct {
	// the name of the database
	Name string
	// the url that the zip archive was downloaded from
	ArchiveURL string
	// whether this database should make any network requests
	Offline bool
	// the path to the zip archive on disk
	StoredAt string
	// the vulnerabilities that are loaded into this database
	vulnerabilities []osvschema.Vulnerability
	// User agent to query with
	UserAgent string
}

var ErrOfflineDatabaseNotFound = errors.New("no offline version of the OSV database is available")

func fetchRemoteArchiveCRC32CHash(ctx context.Context, url string) (uint32, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)

	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("db host returned %s", resp.Status)
	}

	for _, value := range resp.Header.Values("X-Goog-Hash") {
		if strings.HasPrefix(value, "crc32c=") {
			value = strings.TrimPrefix(value, "crc32c=")
			out, err := base64.StdEncoding.DecodeString(value)

			if err != nil {
				return 0, fmt.Errorf("could not decode crc32c= checksum: %w", err)
			}

			return binary.BigEndian.Uint32(out), nil
		}
	}

	return 0, errors.New("could not find crc32c= checksum")
}

func fetchLocalArchiveCRC32CHash(data []byte) uint32 {
	return crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
}

func (db *ZipDB) fetchZip(ctx context.Context) ([]byte, error) {
	cache, err := os.ReadFile(db.StoredAt)

	if db.Offline {
		if err != nil {
			return nil, ErrOfflineDatabaseNotFound
		}

		return cache, nil
	}

	if err == nil {
		remoteHash, err := fetchRemoteArchiveCRC32CHash(ctx, db.ArchiveURL)

		if err != nil {
			return nil, err
		}

		if fetchLocalArchiveCRC32CHash(cache) == remoteHash {
			return cache, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.ArchiveURL, nil)

	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	if db.UserAgent != "" {
		req.Header.Set("User-Agent", db.UserAgent)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("db host returned %s", resp.Status)
	}

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
		slog.Warn(fmt.Sprintf("Failed to save database to %s: %v\n", db.StoredAt, err))
	}

	return body, nil
}

// Loads the given zip file into the database as an OSV.
// It is assumed that the file is JSON and in the working directory of the db
func (db *ZipDB) loadZipFile(zipFile *zip.File) {
	file, err := zipFile.Open()
	if err != nil {
		slog.Warn(fmt.Sprintf("Could not read %s: %v\n", zipFile.Name, err))

		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		slog.Warn(fmt.Sprintf("Could not read %s: %v\n", zipFile.Name, err))

		return
	}

	var vulnerability osvschema.Vulnerability

	if err := json.Unmarshal(content, &vulnerability); err != nil {
		slog.Warn(fmt.Sprintf("%s is not a valid JSON file: %v\n", zipFile.Name, err))

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
func (db *ZipDB) load(ctx context.Context) error {
	db.vulnerabilities = []osvschema.Vulnerability{}

	body, err := db.fetchZip(ctx)

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

func NewZippedDB(ctx context.Context, dbBasePath, name, url, userAgent string, offline bool) (*ZipDB, error) {
	db := &ZipDB{
		Name:       name,
		ArchiveURL: url,
		Offline:    offline,
		StoredAt:   path.Join(dbBasePath, name, "all.zip"),
		UserAgent:  userAgent,
	}
	if err := db.load(ctx); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

func (db *ZipDB) Vulnerabilities(includeWithdrawn bool) []osvschema.Vulnerability {
	if includeWithdrawn {
		return db.vulnerabilities
	}

	var vulnerabilities []osvschema.Vulnerability

	for _, vulnerability := range db.vulnerabilities {
		if vulnerability.Withdrawn.IsZero() {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

// TODO: Move this to another file.
func VulnerabilitiesAffectingPackage(allVulns []osvschema.Vulnerability, pkg imodels.PackageInfo) []*osvschema.Vulnerability {
	var vulnerabilities []*osvschema.Vulnerability

	for _, vulnerability := range allVulns {
		if vulns.IsAffected(vulnerability, pkg) && !vulns.Include(vulnerabilities, vulnerability) {
			vulnerabilities = append(vulnerabilities, &vulnerability)
		}
	}

	return vulnerabilities
}

func (db *ZipDB) Check(pkgs []imodels.PackageInfo) ([]*osvschema.Vulnerability, error) {
	allVulns := db.Vulnerabilities(false)
	vulnerabilities := make([]*osvschema.Vulnerability, 0, len(pkgs))

	for _, pkg := range pkgs {
		vulnerabilities = append(vulnerabilities, VulnerabilitiesAffectingPackage(allVulns, pkg)...)
	}

	return vulnerabilities, nil
}
