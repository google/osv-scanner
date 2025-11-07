package localmatcher_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

const userAgent = "osv-scanner_test/" + version.OSVVersion

func expectDBToHaveOSVs(
	t *testing.T,
	db *localmatcher.ZipDB,
	expect []*osvschema.Vulnerability,
) {
	t.Helper()

	vulns := db.Vulnerabilities

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].GetId() < vulns[j].GetId()
	})
	sort.Slice(expect, func(i, j int) bool {
		return expect[i].GetId() < expect[j].GetId()
	})

	if diff := cmp.Diff(expect, vulns, protocmp.Transform()); diff != "" {
		t.Errorf("db is missing some vulnerabilities (-want +got):\n%s", diff)
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

func writeOSVsZip(t *testing.T, w http.ResponseWriter, osvs map[string]*osvschema.Vulnerability) (int, error) {
	t.Helper()

	z := zipOSVs(t, osvs)

	w.Header().Add("x-goog-hash", "crc32c="+computeCRC32CHash(t, z))

	return w.Write(z)
}

func zipOSVs(t *testing.T, osvs map[string]*osvschema.Vulnerability) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	for fp, osv := range osvs {
		data, err := protojson.Marshal(osv)
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

	_, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, true, nil)

	if !errors.Is(err, localmatcher.ErrOfflineDatabaseNotFound) {
		t.Errorf("expected \"%v\" error but got \"%v\"", localmatcher.ErrOfflineDatabaseNotFound, err)
	}
}

func TestNewZippedDB_Offline_WithCache(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("a server request was made when running offline")
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), zipOSVs(t, map[string]*osvschema.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
		"GHSA-4.json": {Id: "GHSA-4"},
		"GHSA-5.json": {Id: "GHSA-5"},
	}))

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, true, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_BadZip(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not a zip"))
	})

	_, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_UnsupportedProtocol(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	_, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", "file://hello-world", userAgent, false, nil)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_Online_WithoutCache(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]*osvschema.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		})
	})

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithoutCacheAndNoHashHeader(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]*osvschema.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		}))
	})

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithSameCache(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
	}

	testDir := testutility.CreateTestDir(t)

	cache := zipOSVs(t, map[string]*osvschema.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
	})

	ts := createZipServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("unexpected %s request", r.Method)
		}

		w.Header().Add("x-goog-hash", "crc32c="+computeCRC32CHash(t, cache))

		_, _ = w.Write(cache)
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), cache)

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithDifferentCache(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
		{Id: "GHSA-4"},
		{Id: "GHSA-5"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]*osvschema.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		})
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), zipOSVs(t, map[string]*osvschema.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
	}))

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_Online_WithCacheButNoHashHeader(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipOSVs(t, map[string]*osvschema.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
			"GHSA-4.json": {Id: "GHSA-4"},
			"GHSA-5.json": {Id: "GHSA-5"},
		}))
	})

	cacheWrite(t, determineStoredAtPath(testDir, "my-db"), zipOSVs(t, map[string]*osvschema.Vulnerability{
		"GHSA-1.json": {Id: "GHSA-1"},
		"GHSA-2.json": {Id: "GHSA-2"},
		"GHSA-3.json": {Id: "GHSA-3"},
	}))

	_, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err == nil {
		t.Errorf("expected an error but did not get one")
	}
}

func TestNewZippedDB_Online_WithBadCache(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{
		{Id: "GHSA-1"},
		{Id: "GHSA-2"},
		{Id: "GHSA-3"},
	}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]*osvschema.Vulnerability{
			"GHSA-1.json": {Id: "GHSA-1"},
			"GHSA-2.json": {Id: "GHSA-2"},
			"GHSA-3.json": {Id: "GHSA-3"},
		})
	})

	cacheWriteBad(t, determineStoredAtPath(testDir, "my-db"), "this is not json!")

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_FileChecks(t *testing.T) {
	t.Parallel()

	osvs := []*osvschema.Vulnerability{{Id: "GHSA-1234"}, {Id: "GHSA-4321"}}

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]*osvschema.Vulnerability{
			"file.json": {Id: "GHSA-1234"},
			// only files with .json suffix should be loaded
			"file.yaml": {Id: "GHSA-5678"},
			// (no longer) special case for the GH security database
			"advisory-database-main/advisories/unreviewed/file.json": {Id: "GHSA-4321"},
		})
	})

	db, err := localmatcher.NewZippedDB(t.Context(), testDir, "my-db", ts.URL, userAgent, false, nil)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	if db.Partial != false {
		t.Errorf("db is incorrectly marked as partially loaded")
	}
	expectDBToHaveOSVs(t, db, osvs)
}

func TestNewZippedDB_WithSpecificPackages(t *testing.T) {
	t.Parallel()

	testDir := testutility.CreateTestDir(t)

	ts := createZipServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = writeOSVsZip(t, w, map[string]*osvschema.Vulnerability{
			"GHSA-1.json": {
				Id:       "GHSA-1",
				Affected: []*osvschema.Affected{},
			},
			"GHSA-2.json": {
				Id: "GHSA-2",
				Affected: []*osvschema.Affected{
					{Package: &osvschema.Package{Name: "pkg-1"}},
				},
			},
			"GHSA-3.json": {
				Id: "GHSA-3",
			},
			"GHSA-4.json": {
				Id: "GHSA-4",
				Affected: []*osvschema.Affected{
					{Package: &osvschema.Package{Name: "pkg-2"}},
				},
			},
			"GHSA-5.json": {
				Id: "GHSA-5",
				Affected: []*osvschema.Affected{
					{Package: &osvschema.Package{Name: "pkg-2"}},
					{Package: &osvschema.Package{Name: "pkg-1"}},
				},
			},
			"GHSA-6.json": {
				Id: "GHSA-6",
				Affected: []*osvschema.Affected{
					{Package: &osvschema.Package{Name: "pkg-3"}},
					{Package: &osvschema.Package{Name: "pkg-2"}},
				},
			},
		})
	})

	db, err := localmatcher.NewZippedDB(
		t.Context(),
		testDir,
		"my-db",
		ts.URL,
		userAgent,
		false,
		[]*extractor.Package{{Name: "pkg-1"}, {Name: "pkg-3"}},
	)

	if err != nil {
		t.Fatalf("unexpected error \"%v\"", err)
	}

	// we are loaded for specific packages
	if db.Partial != true {
		t.Errorf("db is incorrectly marked as fully loaded")
	}

	expectDBToHaveOSVs(t, db, []*osvschema.Vulnerability{
		{
			Id: "GHSA-2",
			Affected: []*osvschema.Affected{
				{Package: &osvschema.Package{Name: "pkg-1"}},
			},
		},
		{
			Id: "GHSA-5",
			Affected: []*osvschema.Affected{
				{Package: &osvschema.Package{Name: "pkg-2"}},
				{Package: &osvschema.Package{Name: "pkg-1"}},
			},
		},
		{
			Id: "GHSA-6",
			Affected: []*osvschema.Affected{
				{Package: &osvschema.Package{Name: "pkg-3"}},
				{Package: &osvschema.Package{Name: "pkg-2"}},
			},
		},
	})
}
