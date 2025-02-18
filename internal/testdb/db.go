package testdb

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/imodels/ecosystem"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/reporter"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func fetchLocalArchiveCRC32CHash(data []byte) uint32 {
	return crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
}

// extractEcosystem attempts to extract the ecosystem being requested for the given http.Request
func extractEcosystem(r *http.Request) (ecosystem.Parsed, error) {
	matches := cachedregexp.MustCompile(`/(.+)/all\.zip`).FindStringSubmatch(r.URL.Path)

	if len(matches) != 2 {
		return ecosystem.Parsed{}, fmt.Errorf("failed to extract ecosystem from %s", r.URL.Path)
	}

	return ecosystem.Parsed{Ecosystem: osvschema.Ecosystem(matches[1])}, nil
}

// NewZipDBCacheServer creates a httptest.Server which acts like the osv-vulnerabilities
// database storage server, except that it caches the databases to disk for subsequent requests
func NewZipDBCacheServer() *httptest.Server {
	l, err := localmatcher.NewLocalMatcher(
		&reporter.VoidReporter{},
		os.TempDir()+"/osv-scanner/dbs",
		"osv-scanner_scan/"+version.OSVVersion+"/tests",
		true,
	)

	if err != nil {
		panic("failed to create local matcher")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco, err := extractEcosystem(r)

		if err != nil {
			http.Error(w,
				fmt.Sprintf("(test server) error: %v", err),
				http.StatusInternalServerError,
			)

			return
		}

		db, err := l.LoadEcosystem(r.Context(), eco)

		if err != nil {
			http.Error(w,
				fmt.Sprintf("(test server) failed to load %s database: %v", eco, err),
				http.StatusInternalServerError,
			)

			return
		}

		b, err := os.ReadFile(db.StoredAt)

		if err != nil {
			http.Error(w,
				fmt.Sprintf("(test server) failed to read %s database at %s: %v", eco, db.StoredAt, err),
				http.StatusInternalServerError,
			)

			return
		}

		hash := fetchLocalArchiveCRC32CHash(b)

		w.Header().Add("x-goog-hash", "crc32c="+base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32([]byte{}, hash)))

		_, _ = w.Write(b)
	}))

	return ts
}
