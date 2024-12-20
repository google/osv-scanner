package osvdev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/sync/errgroup"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryBatchEndpoint = "/v1/querybatch"
	QueryEndpoint      = "/v1/query"
	// GetEndpoint is the URL for getting vulnerabilities from OSV.
	GetEndpoint = "/v1/vulns"
	// DetermineVersionEndpoint is the URL for posting determineversion queries to OSV.
	DetermineVersionEndpoint = "/v1experimental/determineversion"

	// MaxQueriesPerQueryBatchRequest is a limit set in osv.dev's API, so is not configurable
	MaxQueriesPerQueryBatchRequest = 1000
)

type OSVClient struct {
	HttpClient  http.Client
	Config      ClientConfig
	BaseHostURL string
}

// GetVulnsByID is an interface to this endpoint: https://google.github.io/osv.dev/get-v1-vulns/
func (c *OSVClient) GetVulnsByID(ctx context.Context, id string) (*models.Vulnerability, error) {
	resp, err := c.makeRetryRequest(func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseHostURL+GetEndpoint+"/"+id, nil)
		if err != nil {
			return nil, err
		}
		if c.Config.UserAgent != "" {
			req.Header.Set("User-Agent", c.Config.UserAgent)
		}

		return c.HttpClient.Do(req)
	})

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var vuln models.Vulnerability
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// QueryBatch is an interface to this endpoint: https://google.github.io/osv.dev/post-v1-querybatch/
func (c *OSVClient) QueryBatch(ctx context.Context, queries []*Query) (*BatchedResponse, error) {
	// API has a limit of how many queries are in one batch
	queryChunks := chunkBy(queries, MaxQueriesPerQueryBatchRequest)
	totalOsvRespBatched := make([][]MinimalResponse, len(queryChunks))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(c.Config.MaxConcurrentBatchRequests)
	for batchIndex, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}

		g.Go(func() error {
			// exit early if another hydration request has already failed
			// results are thrown away later, so avoid needless work
			if ctx.Err() != nil {
				return nil
			}

			resp, err := c.makeRetryRequest(func() (*http.Response, error) {
				// Make sure request buffer is inside retry, if outside
				// http request would finish the buffer, and retried requests would be empty
				requestBuf := bytes.NewBuffer(requestBytes)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseHostURL+QueryBatchEndpoint, requestBuf)
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				if c.Config.UserAgent != "" {
					req.Header.Set("User-Agent", c.Config.UserAgent)
				}

				return c.HttpClient.Do(req)
			})
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var osvResp BatchedResponse
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&osvResp)
			if err != nil {
				return err
			}

			// Store batch results in the corresponding index to maintain original query order.
			totalOsvRespBatched[batchIndex] = osvResp.Results

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	totalOsvResp := BatchedResponse{
		Results: make([]MinimalResponse, 0, len(queries)),
	}
	for _, results := range totalOsvRespBatched {
		totalOsvResp.Results = append(totalOsvResp.Results, results...)
	}

	return &totalOsvResp, nil
}

// Query is an interface to this endpoint: https://google.github.io/osv.dev/post-v1-query/
func (c *OSVClient) Query(ctx context.Context, query *Query) (*Response, error) {
	requestBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	requestBuf := bytes.NewBuffer(requestBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseHostURL+QueryEndpoint, requestBuf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.Config.UserAgent != "" {
		req.Header.Set("User-Agent", c.Config.UserAgent)
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var osvResp Response
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&osvResp)
	if err != nil {
		return nil, err
	}

	return &osvResp, nil
}

// ExperimentalDetermineVersion
func (c *OSVClient) ExperimentalDetermineVersion(ctx context.Context, query *DetermineVersionsRequest) (*DetermineVersionResponse, error) {
	requestBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeRetryRequest(func() (*http.Response, error) {
		// Make sure request buffer is inside retry, if outside
		// http request would finish the buffer, and retried requests would be empty
		requestBuf := bytes.NewBuffer(requestBytes)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseHostURL+DetermineVersionEndpoint, requestBuf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.Config.UserAgent != "" {
			req.Header.Set("User-Agent", c.Config.UserAgent)
		}

		return http.DefaultClient.Do(req)
	})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result DetermineVersionResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// makeRetryRequest will return an error on both network errors, and if the response is not 200
func (c *OSVClient) makeRetryRequest(action func() (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := range c.Config.MaxRetryAttempts {
		// rand is initialized with a random number (since go1.20), and is also safe to use concurrently
		// we do not need to use a cryptographically secure random jitter, this is just to spread out the retry requests
		// #nosec G404
		jitterAmount := (rand.Float64() * float64(c.Config.JitterMultiplier) * float64(i))
		time.Sleep(time.Duration(i*i)*time.Second + time.Duration(jitterAmount*1000)*time.Millisecond)

		resp, err = action()
		if err == nil {
			// Check the response for HTTP errors
			err = checkResponseError(resp)
			if err == nil {
				break
			}
		}
	}

	return resp, err
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
	defer resp.Body.Close()

	return fmt.Errorf("server response error: %s", string(respBuf))
}

// From: https://stackoverflow.com/a/72408490
func chunkBy[T any](items []T, chunkSize int) [][]T {
	chunks := make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}

	return append(chunks, items)
}
