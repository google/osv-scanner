package localmatcher

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels"
	"github.com/google/osv-scanner/v2/internal/utility/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
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
	Vulnerabilities []*osvschema.Vulnerability
	// User agent to query with
	UserAgent string

	// whether this database only has some of the advisories
	// loaded from the underlying zip file
	Partial bool
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
		if after, ok := strings.CutPrefix(value, "crc32c="); ok {
			value = after
			out, err := base64.StdEncoding.DecodeString(value)

			if err != nil {
				return 0, fmt.Errorf("could not decode crc32c= checksum: %w", err)
			}

			return binary.BigEndian.Uint32(out), nil
		}
	}

	return 0, errors.New("could not find crc32c= checksum")
}

func fetchLocalArchiveCRC32CHash(f *os.File) (uint32, error) {
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))

	if _, err := io.Copy(h, f); err != nil {
		return 0, err
	}

	return h.Sum32(), nil
}

func (db *ZipDB) fetchZip(ctx context.Context) (*os.File, error) {
	f, err := os.Open(db.StoredAt)

	if db.Offline {
		if err != nil {
			return nil, ErrOfflineDatabaseNotFound
		}

		return f, nil
	}

	if err == nil {
		remoteHash, err := fetchRemoteArchiveCRC32CHash(ctx, db.ArchiveURL)

		if err != nil {
			return nil, err
		}

		localHash, err := fetchLocalArchiveCRC32CHash(f)

		if err != nil {
			return nil, err
		}

		if remoteHash == localHash {
			return f, nil
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

	err = os.MkdirAll(path.Dir(db.StoredAt), 0750)

	if err != nil {
		return nil, fmt.Errorf("could not create cache directory: %w", err)
	}

	f, err = os.OpenFile(db.StoredAt, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	if err != nil {
		return nil, fmt.Errorf("could not create cache file: %w", err)
	}

	_, err = io.Copy(f, resp.Body)

	if err != nil {
		return nil, fmt.Errorf("could not write cache file: %w", err)
	}

	_, _ = f.Seek(0, io.SeekStart)

	return f, nil
}

func mightAffectPackages(v *osvschema.Vulnerability, names []string) bool {
	for _, affected := range v.GetAffected() {
		for _, name := range names {
			if affected.GetPackage().GetName() == name {
				return true
			}

			// "name" will be the git repository in the case of the GIT ecosystem
			for _, ran := range affected.GetRanges() {
				if vulns.NormalizeRepo(ran.GetRepo()) == vulns.NormalizeRepo(name) {
					return true
				}
			}
		}
	}

	return false
}

// Loads the given zip file into the database as an OSV.
// It is assumed that the file is JSON and in the working directory of the db
func (db *ZipDB) loadZipFile(zipFile *zip.File, names []string) {
	file, err := zipFile.Open()
	if err != nil {
		cmdlogger.Warnf("Could not read %s: %v", zipFile.Name, err)

		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		cmdlogger.Warnf("Could not read %s: %v", zipFile.Name, err)

		return
	}

	vulnerability := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal(content, vulnerability); err != nil {
		cmdlogger.Warnf("%s is not a valid JSON file: %v", zipFile.Name, err)

		return
	}

	// if we have been provided a list of package names, only load advisories
	// that might actually affect those packages, rather than all advisories
	if len(names) == 0 || mightAffectPackages(vulnerability, names) {
		db.Vulnerabilities = append(db.Vulnerabilities, vulnerability)
	}
}

// load fetches a zip archive of the OSV database and loads known vulnerabilities
// from it (which are assumed to be in json files following the OSV spec).
//
// If a list of package names is provided, then only advisories with at least
// one affected entry for a listed package will be loaded.
//
// Internally, the archive is cached along with the date that it was fetched
// so that a new version of the archive is only downloaded if it has been
// modified, per HTTP caching standards.
func (db *ZipDB) load(ctx context.Context, names []string) error {
	db.Vulnerabilities = []*osvschema.Vulnerability{}

	f, err := db.fetchZip(ctx)

	if err != nil {
		return err
	}

	defer f.Close()

	s, err := f.Stat()

	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(f, s.Size())
	if err != nil {
		return fmt.Errorf("could not read OSV database archive: %w", err)
	}

	// Read all the files from the zip archive
	for _, zipFile := range zipReader.File {
		if !strings.HasSuffix(zipFile.Name, ".json") {
			continue
		}

		db.loadZipFile(zipFile, names)
	}

	return nil
}

func NewZippedDB(ctx context.Context, dbBasePath, name, url, userAgent string, offline bool, invs []*extractor.Package) (*ZipDB, error) {
	db := &ZipDB{
		Name:       name,
		ArchiveURL: url,
		Offline:    offline,
		StoredAt:   path.Join(dbBasePath, name, "all.zip"),
		UserAgent:  userAgent,

		// we only fully load the database if we're not provided a list of packages
		Partial: len(invs) != 0,
	}
	names := make([]string, 0, len(invs))

	// map the packages to their names ahead of loading,
	// to make things simpler and reduce double working
	for _, inv := range invs {
		in := imodels.FromInventory(inv)
		names = append(names, in.Name())
	}

	if err := db.load(ctx, names); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

// VulnerabilitiesAffectingPackage returns the vulnerabilities that affects the provided package
//
// TODO: Move this to another file.
func VulnerabilitiesAffectingPackage(allVulns []*osvschema.Vulnerability, pkg imodels.PackageInfo) []*osvschema.Vulnerability {
	var vulnerabilities []*osvschema.Vulnerability

	for _, vulnerability := range allVulns {
		if vulnerability.GetWithdrawn() == nil && vulns.IsAffected(vulnerability, pkg) && !vulns.Include(vulnerabilities, vulnerability) {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}
