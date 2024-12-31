package osvdev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/sync/errgroup"
)

const (
	QueryBatchEndpoint = "/v1/querybatch"
	QueryEndpoint      = "/v1/query"
	GetEndpoint        = "/v1/vulns"

	// DetermineVersionEndpoint is the URL for posting determineversion queries to OSV.
	DetermineVersionEndpoint = "/v1experimental/determineversion"

	// MaxQueriesPerQueryBatchRequest is a limit set in osv.dev's API, so is not configurable
	MaxQueriesPerQueryBatchRequest = 1000
)

type OSVClient struct {
	HTTPClient  *http.Client
	Config      ClientConfig
	BaseHostURL string
}

// DefaultClient() creates a new OSVClient with default settings
func DefaultClient() *OSVClient {
	return &OSVClient{
		HTTPClient:  http.DefaultClient,
		Config:      DefaultConfig(),
		BaseHostURL: "https://api.osv.dev",
	}
}

// GetVulnByID is an interface to this endpoint: https://google.github.io/osv.dev/get-v1-vulns/
func (c *OSVClient) GetVulnByID(ctx context.Context, id string) (*models.Vulnerability, error) {
	resp, err := c.makeRetryRequest(func(client *http.Client) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseHostURL+GetEndpoint+"/"+id, nil)
		if err != nil {
			return nil, err
		}
		if c.Config.UserAgent != "" {
			req.Header.Set("User-Agent", c.Config.UserAgent)
		}

		return client.Do(req)
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
// This function performs paging invisibly until the context expires, after which all pages that has already
// been retrieved are returned.
//
// See if next_page_token field in the response is fully filled out to determine if there are extra pages remaining
func (c *OSVClient) QueryBatch(ctx context.Context, queries []*Query) (*BatchedResponse, error) {
	// API has a limit of how many queries are in one batch
	queryChunks := chunkBy(queries, MaxQueriesPerQueryBatchRequest)
	totalOsvRespBatched := make([][]MinimalResponse, len(queryChunks))

	g, errGrpCtx := errgroup.WithContext(ctx)
	g.SetLimit(c.Config.MaxConcurrentBatchRequests)
	for batchIndex, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}

		g.Go(func() error {
			// exit early if another hydration request has already failed
			// results are thrown away later, so avoid needless work
			if errGrpCtx.Err() != nil {
				return nil
			}

			resp, err := c.makeRetryRequest(func(client *http.Client) (*http.Response, error) {
				// Make sure request buffer is inside retry, if outside
				// http request would finish the buffer, and retried requests would be empty
				requestBuf := bytes.NewBuffer(requestBytes)
				req, err := http.NewRequestWithContext(errGrpCtx, http.MethodPost, c.BaseHostURL+QueryBatchEndpoint, requestBuf)
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				if c.Config.UserAgent != "" {
					req.Header.Set("User-Agent", c.Config.UserAgent)
				}

				return client.Do(req)
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

	// --- Paging logic ---
	var errToReturn error
	nextPageQueries := []*Query{}
	nextPageIndexMap := []int{}
	for i, res := range totalOsvResp.Results {
		if res.NextPageToken == "" {
			continue
		}

		query := *queries[i]
		query.PageToken = res.NextPageToken
		nextPageQueries = append(nextPageQueries, &query)
		nextPageIndexMap = append(nextPageIndexMap, i)
	}

	if len(nextPageQueries) > 0 {
		// If context is cancelled or deadline exceeded, return now
		if ctx.Err() != nil {
			return &totalOsvResp, &DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		nextPageResp, err := c.QueryBatch(ctx, nextPageQueries)
		if err != nil {
			var dpr *DuringPagingError
			if ok := errors.As(err, &dpr); ok {
				dpr.PageDepth += 1
				errToReturn = dpr
			} else {
				errToReturn = &DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		// Whether there is an error or not, if there is any data,
		// we want to save and return what we got.
		if nextPageResp != nil {
			for i, res := range nextPageResp.Results {
				totalOsvResp.Results[nextPageIndexMap[i]].Vulns = append(totalOsvResp.Results[nextPageIndexMap[i]].Vulns, res.Vulns...)
				// Set next page token so caller knows whether this is all of the results
				// even if it is being cancelled.
				totalOsvResp.Results[nextPageIndexMap[i]].NextPageToken = res.NextPageToken
			}
		}
	}

	return &totalOsvResp, errToReturn
}

// Query is an interface to this endpoint: https://google.github.io/osv.dev/post-v1-query/
// This function performs paging invisibly until the context expires, after which all pages that has already
// been retrieved are returned.
//
// See if next_page_token field in the response is fully filled out to determine if there are extra pages remaining
func (c *OSVClient) Query(ctx context.Context, query *Query) (*Response, error) {
	requestBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeRetryRequest(func(client *http.Client) (*http.Response, error) {
		requestBuf := bytes.NewBuffer(requestBytes)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseHostURL+QueryEndpoint, requestBuf)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		if c.Config.UserAgent != "" {
			req.Header.Set("User-Agent", c.Config.UserAgent)
		}

		return client.Do(req)
	})

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

	// --- Paging logic ---
	var errToReturn error
	if osvResp.NextPageToken != "" {
		if ctx.Err() != nil {
			return &osvResp, &DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		// Copy query to avoid changing the input
		newQuery := *query
		newQuery.PageToken = osvResp.NextPageToken
		resp, err := c.Query(ctx, &newQuery)
		if err != nil {
			var dpr *DuringPagingError
			if ok := errors.As(err, &dpr); ok {
				dpr.PageDepth += 1
				errToReturn = dpr
			} else {
				errToReturn = &DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		// Whether there is an error or not, if there is any data,
		// we want to save and return what we got.
		if resp != nil {
			osvResp.Vulns = append(osvResp.Vulns, resp.Vulns...)
			// Set next page token so caller knows whether this is all of the results
			// even if it is being cancelled.
			osvResp.NextPageToken = resp.NextPageToken
		}
	}

	return &osvResp, errToReturn
}

// ExperimentalDetermineVersion
func (c *OSVClient) ExperimentalDetermineVersion(ctx context.Context, query *DetermineVersionsRequest) (*DetermineVersionResponse, error) {
	requestBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	resp, err := c.makeRetryRequest(func(client *http.Client) (*http.Response, error) {
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

		return client.Do(req)
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
func (c *OSVClient) makeRetryRequest(action func(client *http.Client) (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	var err error
	var lastErr error

	for i := range c.Config.MaxRetryAttempts {
		// rand is initialized with a random number (since go1.20), and is also safe to use concurrently
		// we do not need to use a cryptographically secure random jitter, this is just to spread out the retry requests
		// #nosec G404
		jitterAmount := (rand.Float64() * float64(c.Config.JitterMultiplier) * float64(i))
		time.Sleep(
			time.Duration(math.Pow(float64(i), c.Config.BackoffDurationExponential)*c.Config.BackoffDurationMultiplier*1000)*time.Millisecond +
				time.Duration(jitterAmount*1000)*time.Millisecond)

		resp, err = action(c.HTTPClient)

		// Don't retry, since deadline has already been exceeded
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		// The network request itself failed, did not even get a response
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: request failed: %w", i+1, err)
			continue
		}

		// Everything is fine
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		errBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: failed to read response: %w", i+1, err)
			continue
		}

		// Special case for too many requests, it should try again after a delay.
		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("attempt %d: too many requests: status=%q body=%s", i+1, resp.Status, errBody)
			continue
		}

		// Otherwise any other 400 error should be fatal, as the request we are sending is incorrect
		// Retrying won't make a difference
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("client error: status=%q body=%s", resp.Status, errBody)
		}

		// Most likely a 500 >= error
		lastErr = fmt.Errorf("server error: status=%q body=%s", resp.Status, errBody)
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// From: https://stackoverflow.com/a/72408490
func chunkBy[T any](items []T, chunkSize int) [][]T {
	chunks := make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}

	return append(chunks, items)
}
