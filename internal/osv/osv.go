package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api.osv.dev/v1/querybatch"
	// GetEndpoint is the URL for getting vulenrabilities from OSV.
	GetEndpoint = "https://api.osv.dev/v1/vulns"
	// BaseVulnerabilityURL is the base URL for detailed vulnerability views.
	BaseVulnerabilityURL = "https://osv.dev/vulnerability/"
	// MaxQueriesPerRequest splits up querybatch into multiple requests if
	// number of queries exceed this number
	MaxQueriesPerRequest = 1000
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
	Source  models.SourceInfo `json:"omit"`
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
	_chunks := make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, _chunks = items[chunkSize:], append(_chunks, items[0:chunkSize:chunkSize])
	}
	return append(_chunks, items)
}

// checkResponseError checks if the response has an error.
func checkResponseError(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read error response from server: %w", err)
	}

	return fmt.Errorf("server response error: %s", string(respBuf))
}

func MakeRequest(request BatchedQuery) (*BatchedResponse, error) {
	// API has a limit of 1000 bulk query per request
	queryChunks := chunkBy(request.Queries, MaxQueriesPerRequest)
	var totalOsvResp BatchedResponse

	for _, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}
		requestBuf := bytes.NewBuffer(requestBytes)

		resp, err := http.Post(QueryEndpoint, "application/json", requestBuf)
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

// Get a Vulnerabiltiy for the given ID.
func Get(id string) (*models.Vulnerability, error) {
	resp, err := http.Get(GetEndpoint + "/" + id)
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
	// TODO(ochang): Parallelize requests, or implement batch GET.
	hydrated := HydratedBatchedResponse{}

	for _, response := range resp.Results {
		result := Response{}
		for _, vuln := range response.Vulns {
			vuln, err := Get(vuln.ID)
			if err != nil {
				return nil, err
			}

			result.Vulns = append(result.Vulns, *vuln)
		}
		hydrated.Results = append(hydrated.Results, result)
	}
	return &hydrated, nil
}
