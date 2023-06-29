package offline_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"

	"github.com/google/osv-scanner/internal/offline"
	"github.com/google/osv-scanner/pkg/models"
)

func createTestDir(t *testing.T) (string, func()) {
	t.Helper()

	p, err := os.MkdirTemp("", "osv-scanner-test-*")
	if err != nil {
		t.Fatal("could not create test directory")
	}

	return p, func() {
		_ = os.RemoveAll(p)
	}
}

func expectDBToHaveOSVs(
	t *testing.T,
	db interface {
		Vulnerabilities(includeWithdrawn bool) []models.Vulnerability
	},
	actual []models.Vulnerability,
) {
	t.Helper()

	vulns := db.Vulnerabilities(true)

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID < vulns[j].ID
	})
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].ID < actual[j].ID
	})

	if !reflect.DeepEqual(vulns, actual) {
		t.Errorf("db is missing some vulnerabilities: %v vs %v", vulns, actual)
	}
}

func cacheWrite(t *testing.T, storedAt string, cache offline.Cache) {
	t.Helper()

	cacheContents, err := json.Marshal(cache)

	if err == nil {
		err = os.MkdirAll(path.Dir(storedAt), 0750)

		if err == nil {
			//nolint:gosec // being world readable is fine
			err = os.WriteFile(storedAt, cacheContents, 0644)
		}
	}

	if err != nil {
		t.Errorf("unexpected error with cache: %v", err)
	}
}

func cacheWriteBad(t *testing.T, storedAt string, contents string) {
	t.Helper()

	err := os.MkdirAll(path.Dir(storedAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(storedAt, []byte(contents), 0644)
	}

	if err != nil {
		t.Errorf("unexpected error with cache: %v", err)
	}
}

func createZipServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func()) {
	t.Helper()

	ts := httptest.NewServer(handler)

	return ts, ts.Close
}

func zipOSVs(t *testing.T, osvs map[string]models.Vulnerability) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	for fp, osv := range osvs {
		data, err := json.Marshal(osv)
		if err != nil {
			t.Fatalf("could not marshal %v: %v", osv, err)
		}

		f, err := writer.Create(fp)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(data)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

//nolint:unparam // name might get changed at some point
func determineStoredAtPath(dbBasePath, name string) string {
	return path.Join(dbBasePath, name, "all.zip")
}

func TestNewZippedDB_Offline_WithoutCache(t *testing.T) {
	t.Parallel()

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a server request was made when running offline")
	})
	defer cleanupTestServer()

	_, err := offline.NewZippedDB(testDir, "my-db", ts.URL, true)

	if !errors.Is(err, offline.ErrOfflineDatabaseNotFound) {
		t.Errorf("expected \"%v\" error but got \"%v\"", offline.ErrOfflineDatabaseNotFound, err)
	}
}

func TestNewZippedDB_Offline_WithCache(t *testing.T) {
	t.Parallel()

	date := "Fri, 17 Jun 2022 22:28:13 GMT"
	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
		{ID: "GHSA-4"},
		{ID: "GHSA-5"},
	}

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a server request was made when running offline")
	})
	defer cleanupTestServer()

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), offline.Cache{
		URL:  ts.URL,
		ETag: "",
		Date: date,
		Body: zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		}),
	})

	db, err := offline.NewZippedDB(testDir, "my-db", ts.URL, true)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.UpdatedAt != date {
		t.Errorf("db.UpdatedAt got = \"%s\", want = \"%s\"", db.UpdatedAt, date)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_BadZip(t *testing.T) {
	t.Parallel()

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a zip"))
	})
	defer cleanupTestServer()

	_, err := offline.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_UnsupportedProtocol(t *testing.T) {
	t.Parallel()

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	_, err := offline.NewZippedDB(testDir, "my-db", "file://hello-world", false)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_Online_WithoutCache(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
		{ID: "GHSA-4"},
		{ID: "GHSA-5"},
	}

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		}))
	})
	defer cleanupTestServer()

	db, err := offline.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithCache(t *testing.T) {
	t.Parallel()

	date := "Fri, 18 Jun 2022 22:28:13 GMT"
	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
	}

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if dateHeader := r.Header.Get("If-Modified-Since"); dateHeader != date {
			t.Errorf("incorrect Date header: got = \"%s\", want = \"%s\"", dateHeader, date)
		}

		w.WriteHeader(http.StatusNotModified)
	})
	defer cleanupTestServer()

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), offline.Cache{
		URL:  ts.URL,
		ETag: "",
		Date: date,
		Body: zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		}),
	})

	db, err := offline.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.UpdatedAt != date {
		t.Errorf("db.UpdatedAt got = \"%s\", want = \"%s\"", db.UpdatedAt, date)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithOldCache(t *testing.T) {
	t.Parallel()

	date := "Fri, 17 Jun 2022 22:28:13 GMT"
	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
		{ID: "GHSA-4"},
		{ID: "GHSA-5"},
	}

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if dateHeader := r.Header.Get("If-Modified-Since"); dateHeader != date {
			t.Errorf("incorrect Date header: got = \"%s\", want = \"%s\"", dateHeader, date)
		}

		w.Header().Set("Date", "Today")
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		}))
	})
	defer cleanupTestServer()

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), offline.Cache{
		URL:  ts.URL,
		ETag: "",
		Date: date,
		Body: zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		}),
	})

	db, err := offline.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.UpdatedAt != "Today" {
		t.Errorf("db.UpdatedAt got = \"%s\", want = \"%s\"", db.UpdatedAt, "Today")
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithBadCache(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
	}

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		}))
	})
	defer cleanupTestServer()

	cacheWriteBad(t, determineStoredAtPath(testDir, "my-db"), "this is not json!")

	db, err := offline.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_FileChecks(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{{ID: "GHSA-1234"}, {ID: "GHSA-4321"}}

	testDir, cleanupTestDir := createTestDir(t)
	defer cleanupTestDir()

	ts, cleanupTestServer := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"file.json": {ID: "GHSA-1234"},
			// only files with .json suffix should be loaded
			"file.yaml": {ID: "GHSA-5678"},
			// (no longer) special case for the GH security database
			"advisory-database-main/advisories/unreviewed/file.json": {ID: "GHSA-4321"},
		}))
	})
	defer cleanupTestServer()

	db, err := offline.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}
