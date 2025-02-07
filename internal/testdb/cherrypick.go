package testdb

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
)

// fetchOSV returns the JSON data for the given OSV ID from the OSV API
func fetchOSV(id string) ([]byte, error) {
	//nolint:noctx // we don't need a context here
	resp, err := http.Get("https://api.osv.dev/v1/vulns/" + id)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch osv %s: %s", id, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return data, err
}

func buildCherryPickedZipDB(advisories []string) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	for _, osv := range advisories {
		data, err := fetchOSV(osv)
		if err != nil {
			return nil, err
		}

		f, err := writer.Create(osv + ".json")
		if err != nil {
			return nil, err
		}
		_, err = f.Write(data)
		if err != nil {
			return nil, err
		}
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// NewZipDBCherryPickServer creates a httptest.Server which acts like the osv-vulnerabilities
// database storage server, except it serves much smaller databases made up of specific advisories
func NewZipDBCherryPickServer(ecosystems map[string][]string) *httptest.Server {
	dbs := make(map[string][]byte, len(ecosystems))

	for eco, advisories := range ecosystems {
		db, err := buildCherryPickedZipDB(advisories)
		if err != nil {
			panic(err)
		}
		dbs[eco] = db
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

		b, ok := dbs[eco.String()]

		if !ok {
			http.Error(w,
				fmt.Sprintf("(test server) no database exists for %s", eco),
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
