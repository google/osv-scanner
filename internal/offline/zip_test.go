package offline_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/google/osv-scanner/internal/offline"
	"github.com/google/osv-scanner/pkg/models"
)

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

type CleanUpZipServerFn = func()

func cachePath(url string) string {
	hash := sha256.Sum256([]byte(url))
	fileName := fmt.Sprintf("osv-detector-%x-db.json", hash)

	return filepath.Join(os.TempDir(), fileName)
}

func cacheWrite(t *testing.T, cache offline.Cache) {
	t.Helper()

	cacheContents, err := json.Marshal(cache)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(cachePath(cache.URL), cacheContents, 0644)
	}

	if err != nil {
		t.Errorf("unexpected error with cache: %v", err)
	}
}

func cacheWriteBad(t *testing.T, url string, contents string) {
	t.Helper()

	//nolint:gosec // being world readable is fine
	err := os.WriteFile(cachePath(url), []byte(contents), 0644)

	if err != nil {
		t.Errorf("unexpected error with cache: %v", err)
	}
}

func createZipServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, CleanUpZipServerFn) {
	t.Helper()

	ts := httptest.NewServer(handler)

	return ts, func() {
		ts.Close()

		_ = os.Remove(cachePath(ts.URL))
	}
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

func TestNewZippedDB_Offline_WithoutCache(t *testing.T) {
	t.Parallel()

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a server request was made when running offline")
	})
	defer cleanup()

	_, err := offline.NewZippedDB("my-db", ts.URL, true)

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

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a server request was made when running offline")
	})
	defer cleanup()

	cacheWrite(t, offline.Cache{
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

	db, err := offline.NewZippedDB("my-db", ts.URL, true)

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

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a zip"))
	})
	defer cleanup()

	_, err := offline.NewZippedDB("my-db", ts.URL, false)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_UnsupportedProtocol(t *testing.T) {
	t.Parallel()

	_, err := offline.NewZippedDB("my-db", "file://hello-world", false)

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

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		}))
	})
	defer cleanup()

	db, err := offline.NewZippedDB("my-db", ts.URL, false)

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

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if dateHeader := r.Header.Get("If-Modified-Since"); dateHeader != date {
			t.Errorf("incorrect Date header: got = \"%s\", want = \"%s\"", dateHeader, date)
		}

		w.WriteHeader(http.StatusNotModified)
	})
	defer cleanup()

	cacheWrite(t, offline.Cache{
		URL:  ts.URL,
		ETag: "",
		Date: date,
		Body: zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		}),
	})

	db, err := offline.NewZippedDB("my-db", ts.URL, false)

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

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
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
	defer cleanup()

	cacheWrite(t, offline.Cache{
		URL:  ts.URL,
		ETag: "",
		Date: date,
		Body: zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		}),
	})

	db, err := offline.NewZippedDB("my-db", ts.URL, false)

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

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		}))
	})
	defer cleanup()

	cacheWriteBad(t, ts.URL, "this is not json!")

	db, err := offline.NewZippedDB("my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_FileChecks(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{{ID: "GHSA-1234"}, {ID: "GHSA-4321"}}

	ts, cleanup := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"file.json": {ID: "GHSA-1234"},
			// only files with .json suffix should be loaded
			"file.yaml": {ID: "GHSA-5678"},
			// (no longer) special case for the GH security database
			"advisory-database-main/advisories/unreviewed/file.json": {ID: "GHSA-4321"},
		}))
	})
	defer cleanup()

	db, err := offline.NewZippedDB("my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}
