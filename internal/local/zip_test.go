package local_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"

	"github.com/google/osv-scanner/internal/local"
	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
)

func expectDBToHaveOSVs(
	t *testing.T,
	db interface {
		Vulnerabilities(includeWithdrawn bool) []models.Vulnerability
	},
	expect []models.Vulnerability,
) {
	t.Helper()

	vulns := db.Vulnerabilities(true)

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID < vulns[j].ID
	})
	sort.Slice(expect, func(i, j int) bool {
		return expect[i].ID < expect[j].ID
	})

	if !reflect.DeepEqual(expect, vulns) {
		t.Errorf("db is missing some vulnerabilities: %v vs %v", expect, vulns)
	}
}

func cacheWrite(t *testing.T, storedAt string, cache []byte) {
	t.Helper()

	err := os.MkdirAll(path.Dir(storedAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(storedAt, cache, 0644)
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

func createZipServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(handler)

	t.Cleanup(ts.Close)

	return ts
}

func computeCRC32CHash(t *testing.T, data []byte) string {
	t.Helper()

	hash := crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))

	return base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32([]byte{}, hash))
}

func writeOSVsZip(t *testing.T, w http.ResponseWriter, osvs map[string]models.Vulnerability) (int, error) {
	t.Helper()

	z := zipOSVs(t, osvs)

	w.Header().Add("x-goog-hash", "crc32c="+computeCRC32CHash(t, z))

	return w.Write(z)
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

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("a server request was made when running offline")
	})

	_, err := local.NewZippedDB(testDir, "my-db", ts.URL, true)

	if !errors.Is(err, local.ErrOfflineDatabaseNotFound) {
		t.Errorf("expected \"%v\" error but got \"%v\"", local.ErrOfflineDatabaseNotFound, err)
	}
}

func TestNewZippedDB_Offline_WithCache(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
		{ID: "GHSA-4"},
		{ID: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("a server request was made when running offline")
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), zipOSVs(t, map[string]models.Vulnerability{
		"GHSA-1.json": {ID: "GHSA-1"},
		"GHSA-2.json": {ID: "GHSA-2"},
		"GHSA-3.json": {ID: "GHSA-3"},
		"GHSA-4.json": {ID: "GHSA-4"},
		"GHSA-5.json": {ID: "GHSA-5"},
	}))

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, true)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_BadZip(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not a zip"))
	})

	_, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_UnsupportedProtocol(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	_, err := local.NewZippedDB(testDir, "my-db", "file://hello-world", false)

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

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		})
	})

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithoutCacheAndNoHashHeader(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
		{ID: "GHSA-4"},
		{ID: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		}))
	})

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithSameCache(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
	}

	testDir := testutility.CreateTestDir(t)

	cache := zipOSVs(t, map[string]models.Vulnerability{
		"GHSA-1.json": {ID: "GHSA-1"},
		"GHSA-2.json": {ID: "GHSA-2"},
		"GHSA-3.json": {ID: "GHSA-3"},
	})

	ts := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("unexpected %s request", r.Method)
		}

		w.Header().Add("x-goog-hash", "crc32c="+computeCRC32CHash(t, cache))

		_, _ = w.Write(cache)
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), cache)

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithDifferentCache(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
		{ID: "GHSA-4"},
		{ID: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		})
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), zipOSVs(t, map[string]models.Vulnerability{
		"GHSA-1.json": {ID: "GHSA-1"},
		"GHSA-2.json": {ID: "GHSA-2"},
		"GHSA-3.json": {ID: "GHSA-3"},
	}))

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithCacheButNoHashHeader(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
			"GHSA-4.json": {ID: "GHSA-4"},
			"GHSA-5.json": {ID: "GHSA-5"},
		}))
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), zipOSVs(t, map[string]models.Vulnerability{
		"GHSA-1.json": {ID: "GHSA-1"},
		"GHSA-2.json": {ID: "GHSA-2"},
		"GHSA-3.json": {ID: "GHSA-3"},
	}))

	_, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_Online_WithBadCache(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{
		{ID: "GHSA-1"},
		{ID: "GHSA-2"},
		{ID: "GHSA-3"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]models.Vulnerability{
			"GHSA-1.json": {ID: "GHSA-1"},
			"GHSA-2.json": {ID: "GHSA-2"},
			"GHSA-3.json": {ID: "GHSA-3"},
		})
	})

	cacheWriteBad(t, determineStoredAtPath(testDir, "my-db"), "this is not json!")

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_FileChecks(t *testing.T) {
	t.Parallel()

	osvs := []models.Vulnerability{{ID: "GHSA-1234"}, {ID: "GHSA-4321"}}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]models.Vulnerability{
			"file.json": {ID: "GHSA-1234"},
			// only files with .json suffix should be loaded
			"file.yaml": {ID: "GHSA-5678"},
			// (no longer) special case for the GH security database
			"advisory-database-main/advisories/unreviewed/file.json": {ID: "GHSA-4321"},
		})
	})

	db, err := local.NewZippedDB(testDir, "my-db", ts.URL, false)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	expectDBToHaveOSVs(t, db, osvs)
}
