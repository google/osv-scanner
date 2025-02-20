package osvdev

import "github.com/ossf/osv-schema/bindings/go/osvschema"

// Package represents a package identifier for OSV.
type Package struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Query represents a query to OSV.
type Query struct {
	Commit    string  `json:"commit,omitempty"`
	Package   Package `json:"package,omitempty"`
	Version   string  `json:"version,omitempty"`
	PageToken string  `json:"page_token,omitempty"`
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
	Vulns         []osvschema.Vulnerability `json:"vulns"`
	NextPageToken string                    `json:"next_page_token"`
}

// MinimalResponse represents an unhydrated response from OSV.
type MinimalResponse struct {
	Vulns         []MinimalVulnerability `json:"vulns"`
	NextPageToken string                 `json:"next_page_token"`
}

// BatchedResponse represents an unhydrated batched response from OSV.
type BatchedResponse struct {
	Results []MinimalResponse `json:"results"`
}

// HydratedBatchedResponse represents a hydrated batched response from OSV.
type HydratedBatchedResponse struct {
	Results []Response `json:"results"`
}

// DetermineVersionHash holds the per file hash and path information for determineversion.
type DetermineVersionHash struct {
	Path string `json:"path"`
	Hash []byte `json:"hash"`
}

// DetermineVersionResponse is the response from the determineversions endpoint
type DetermineVersionResponse struct {
	Matches []struct {
		Score    float64 `json:"score"`
		RepoInfo struct {
			Type    string `json:"type"`
			Address string `json:"address"`
			Tag     string `json:"tag"`
			Version string `json:"version"`
			Commit  string `json:"commit"`
		} `json:"repo_info"`
	} `json:"matches"`
}

// DetermineVersionsRequest is the request format to the determineversions endpoint
type DetermineVersionsRequest struct {
	Name       string                 `json:"name"`
	FileHashes []DetermineVersionHash `json:"file_hashes"`
}
