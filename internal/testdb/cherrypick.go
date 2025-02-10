package testdb

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// a struct to hold the result from each request including an index
// which will be used for sorting the results after they come in
type result struct {
	id  string
	res []byte
	err error
}

// fetchOSVs fetches the OSV data for the given IDs from the OSV API
func fetchOSVs(ids []string) (map[string]result, error) {
	conLimit := 200

	osvs := make(map[string]result, len(ids))

	if len(ids) == 0 {
		return osvs, nil
	}

	// buffered channel which controls the number of concurrent operations
	semaphoreChan := make(chan struct{}, conLimit)
	resultsChan := make(chan *result)

	defer func() {
		close(semaphoreChan)
		close(resultsChan)
	}()

	for _, id := range ids {
		go func(id string) {
			// read from the buffered semaphore channel, which will block if we're
			// already got as many goroutines as our concurrency limit allows
			//
			// when one of those routines finish they'll read from this channel,
			// freeing up a slot to unblock this send
			semaphoreChan <- struct{}{}

			// capture both the osv data and any error that occurred
			osv, err := fetchOSV(id)
			result := &result{id, osv, err}

			resultsChan <- result

			// read from the buffered semaphore to free up a slot to allow
			// another goroutine to start, since this one is wrapping up
			<-semaphoreChan
		}(id)
	}

	var errs []error

	// since we're using a map which might have repeated keys,
	// we have to keep track of how many results we've gotten
	// separately to know when we're done fetching everything
	count := 0

	for {
		result := <-resultsChan
		osvs[result.id] = *result

		if result.err != nil {
			errs = append(errs, result.err)
		}

		count += 1

		if count == len(ids) {
			break
		}
	}

	return osvs, errors.Join(errs...)
}

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

// fetchOSVsAndRelated fetches the OSV data for the given ids from the OSV API,
// along with any related advisories mentioned in the "related" and "aliases"
// fields of each advisory.
func fetchOSVsAndRelated(ids []string) (map[string][]byte, error) {
	initial, err := fetchOSVs(ids)

	// if any of the initial OSVs failed to fetch, return the error since they were
	// explicitly requested and so assumingly are expected to test specific cases
	//
	// (this is different from the related advisories which are fetched implicitly)
	if err != nil {
		return nil, err
	}

	// (might as well assume there's at least one alias per OSV)
	extraIDs := make([]string, 0, len(initial))

	// a map that holds all the OSVs we've fetched, keyed by their id
	all := make(map[string][]byte, len(initial))

	for _, r := range initial {
		var vulnerability osvschema.Vulnerability

		if err := json.Unmarshal(r.res, &vulnerability); err != nil {
			return nil, fmt.Errorf("could not unmarshal JSON data: %w", err)
		}

		// add the advisory to our results
		all[r.id] = r.res

		// for each alias, add it to the list of extra IDs to fetch if we haven't already
		for _, id := range vulnerability.Aliases {
			// if we've already got this OSV, skip it
			if _, ok := all[id]; ok {
				continue
			}

			extraIDs = append(extraIDs, id)
		}

		for _, id := range vulnerability.Related {
			// if we've already got this OSV, skip it
			if _, ok := all[id]; ok {
				continue
			}

			extraIDs = append(extraIDs, id)
		}
	}

	// fetch the related OSVs and add them to the results
	related, _ := fetchOSVs(extraIDs)

	for id, data := range related {
		// a few OVSs have related advisories that don't exist in the osv.dev database
		// typically because their source doesn't have a complete entry in their database
		//
		// e.g. CGA-758j-cqx5-pjx9 has GHSA-vf3q-65gx-324p as an alias, which exists
		// but does not have an ecosystem or package data because the GH advisory
		// database does not yet support the Chainguard ecosystem
		//
		// because of this, we just skip any errors here given these OSVs have not
		// been explicitly requested to be fetched for our tests
		//
		// todo: we should check that we've gotten a 404 specifically
		if data.err != nil {
			// fmt.Printf("error fetching %s: %v\n", id, data.err)
			continue
		}

		all[id] = data.res
	}

	return all, nil
}

func buildCherryPickedZipDB(advisories []string) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	results, err := fetchOSVsAndRelated(advisories)

	if err != nil {
		return nil, err
	}

	for id, data := range results {
		f, err := writer.Create(id + ".json")
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
//
// It takes a map of ecosystems with advisory IDs which will be "cherry-picked" from the osv.dev API
// into an in-memory zip file which the server will serve as the database for each ecosystem.
//
// To help with potential debugging, the cherry-picker will skip any ecosystem whose key starts with
// two slashes (//), so that you can easily play around with ecosystems and advisories without having
// to comment out every single ID for a particular ecosystem (as that could be quite a lot).
func NewZipDBCherryPickServer(ecosystems map[string][]string) *httptest.Server {
	dbs := make(map[string][]byte, len(ecosystems))

	for eco, advisories := range ecosystems {
		if strings.HasPrefix(eco, "//") {
			continue
		}

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
