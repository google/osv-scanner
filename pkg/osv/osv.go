package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/sync/semaphore"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api.osv.dev/v1/querybatch"
	// GetEndpoint is the URL for getting vulenrabilities from OSV.
	GetEndpoint = "https://api.osv.dev/v1/vulns"
	// BaseVulnerabilityURL is the base URL for detailed vulnerability views.
	BaseVulnerabilityURL = "https://osv.dev/"
	// maxQueriesPerRequest splits up querybatch into multiple requests if
	// number of queries exceed this number
	maxQueriesPerRequest  = 1000
	maxConcurrentRequests = 25
)

// Package represents a package identifier for OSV.
type Package struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Query represents a query to OSV.
type Query struct {
	Commit  string            `json:"commit,omitempty"`
	Package Package           `json:"package,omitempty"`
	Version string            `json:"version,omitempty"`
	Source  models.SourceInfo `json:"-"`
}

// BatchedQuery represents a batched query to OSV.
type BatchedQuery struct {
	Queries []*Query `json:"queries"`
}

// MinimalVulnerability represents an unhydrated vulnerability entry from OSV.
type MinimalVulnerability struct {
	ID string `json:"id"`
}

// Response represents a full response from OSV.
type Response struct {
	Vulns []models.Vulnerability `json:"vulns"`
}

// MinimalResponse represents an unhydrated response from OSV.
type MinimalResponse struct {
	Vulns []MinimalVulnerability `json:"vulns"`
}

// BatchedResponse represents an unhydrated batched response from OSV.
type BatchedResponse struct {
	Results []MinimalResponse `json:"results"`
}

// HydratedBatchedResponse represents a hydrated batched response from OSV.
type HydratedBatchedResponse struct {
	Results []Response `json:"results"`
}

// MakeCommitRequest makes a commit hash request.
func MakeCommitRequest(commit string) *Query {
	return &Query{
		Commit: commit,
	}
}

// MakePURLRequest makes a PURL request.
func MakePURLRequest(purl string) *Query {
	return &Query{
		Package: Package{
			PURL: purl,
		},
	}
}

func MakePkgRequest(pkgDetails lockfile.PackageDetails) *Query {
	return &Query{
		Version: pkgDetails.Version,
		// API has trouble parsing requests with both commit and Package details filled ins
		// Commit:  pkgDetails.Commit,
		Package: Package{
			Name:      pkgDetails.Name,
			Ecosystem: string(pkgDetails.Ecosystem),
		},
	}
}

// From: https://stackoverflow.com/a/72408490
func chunkBy[T any](items []T, chunkSize int) [][]T {
	chunks := make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}

	return append(chunks, items)
}

// checkResponseError checks if the response has an error.
func checkResponseError(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read error response from server: %w", err)
	}

	return fmt.Errorf("server response error: %s", string(respBuf))
}

// MakeRequest sends a batched query to osv.dev
func MakeRequest(request BatchedQuery) (*BatchedResponse, error) {
	// API has a limit of 1000 bulk query per request
	queryChunks := chunkBy(request.Queries, maxQueriesPerRequest)
	var totalOsvResp BatchedResponse
	for _, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}
		requestBuf := bytes.NewBuffer(requestBytes)

		resp, err := makeRetryRequest(func() (*http.Response, error) {
			// We do not need a specific context
			//nolint:noctx
			return http.Post(QueryEndpoint, "application/json", requestBuf)
		})
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if err := checkResponseError(resp); err != nil {
			return nil, err
		}

		var osvResp BatchedResponse
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&osvResp)
		if err != nil {
			return nil, err
		}

		totalOsvResp.Results = append(totalOsvResp.Results, osvResp.Results...)
	}

	return &totalOsvResp, nil
}

// Get a Vulnerability for the given ID.
func Get(id string) (*models.Vulnerability, error) {
	resp, err := makeRetryRequest(func() (*http.Response, error) {
		//nolint:noctx
		return http.Get(GetEndpoint + "/" + id)
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	var vuln models.Vulnerability
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// Hydrate fills the results of the batched response with the full
// Vulnerability details.
func Hydrate(resp *BatchedResponse) (*HydratedBatchedResponse, error) {
	hydrated := HydratedBatchedResponse{}
	ctx := context.TODO()
	// Preallocate the array to avoid slice reallocations when inserting later
	hydrated.Results = make([]Response, len(resp.Results))
	for idx := range hydrated.Results {
		hydrated.Results[idx].Vulns =
			make([]models.Vulnerability, len(resp.Results[idx].Vulns))
	}

	errChan := make(chan error)
	rateLimiter := semaphore.NewWeighted(maxConcurrentRequests)

	for batchIdx, response := range resp.Results {
		for resultIdx, vuln := range response.Vulns {
			if err := rateLimiter.Acquire(ctx, 1); err != nil {
				log.Panicf("Failed to acquire semaphore: %v", err)
			}

			go func(id string, batchIdx int, resultIdx int) {
				vuln, err := Get(id)
				if err != nil {
					errChan <- err
				} else {
					hydrated.Results[batchIdx].Vulns[resultIdx] = *vuln
				}

				rateLimiter.Release(1)
			}(vuln.ID, batchIdx, resultIdx)
		}
	}

	// Close error channel when all semaphores are released
	go func() {
		if err := rateLimiter.Acquire(ctx, maxConcurrentRequests); err != nil {
			log.Panicf("Failed to acquire semaphore: %v", err)
		}
		// Always close the error channel
		close(errChan)
	}()

	// Range will exit when channel is closed.
	// Channel will be closed when all semaphores are freed.
	for err := range errChan {
		return nil, err
	}

	return &hydrated, nil
}

func makeRetryRequest(action func() (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	var err error
	retries := 3
	for i := 0; i < retries; i++ {
		resp, err = action()
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	return resp, err
}
