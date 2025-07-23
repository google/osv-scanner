// Package baseimagematcher implements a client for matching base images using the deps.dev API.
package baseimagematcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
)

const (
	maxConcurrentRequests = 1000
	APIEndpoint           = "https://api.deps.dev/v3alpha/querycontainerimages/"
	// DigestSHA256EmptyTar is the canonical sha256 digest of empty tar file -
	// (1024 NULL bytes)
	DigestSHA256EmptyTar = digest.Digest("sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef")
)

// DepsDevBaseImageMatcher is an implementation of clientinterfaces.BaseImageMatcher
// that uses the deps.dev API to match base images.
//
// It sends out requests for every package version and does not perform caching.
type DepsDevBaseImageMatcher struct {
	HTTPClient http.Client
	Config     ClientConfig
}

func (matcher *DepsDevBaseImageMatcher) MatchBaseImages(ctx context.Context, layerMetadata []models.LayerMetadata) ([][]models.BaseImageDetails, error) {
	baseImagesToLayerMap := make([][]models.BaseImageDetails, len(layerMetadata))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	var runningDigest digest.Digest
	for i, l := range layerMetadata {
		diffID := l.DiffID
		if diffID == "" {
			diffID = DigestSHA256EmptyTar
		}

		if runningDigest == "" {
			runningDigest = diffID
		} else {
			runningDigest = digest.FromBytes([]byte(runningDigest + " " + diffID))
		}

		chainID := runningDigest
		g.Go(func() error {
			if ctx.Err() != nil {
				return ctx.Err() // this value doesn't matter to errgroup.Wait(), it will be ctx.Err()
			}

			// If we are erroring for one base image even with retry, we probably should stop
			var err error
			baseImagesToLayerMap[i], err = matcher.queryBaseImagesForChainID(ctx, chainID)

			return err
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return buildBaseImageDetails(layerMetadata, baseImagesToLayerMap), nil
}

// makeRetryRequest will return an error on both network errors, and if the response is not 200 or 404
func (matcher *DepsDevBaseImageMatcher) makeRetryRequest(action func(client *http.Client) (*http.Response, error)) (*http.Response, error) {
	var resp *http.Response
	var err error
	var lastErr error

	for i := range matcher.Config.MaxRetryAttempts {
		// rand is initialized with a random number (since go1.20), and is also safe to use concurrently
		// we do not need to use a cryptographically secure random jitter, this is just to spread out the retry requests
		// #nosec G404
		jitterAmount := (rand.Float64() * float64(matcher.Config.JitterMultiplier) * float64(i))
		time.Sleep(
			time.Duration(math.Pow(float64(i), matcher.Config.BackoffDurationExponential)*matcher.Config.BackoffDurationMultiplier*1000)*time.Millisecond +
				time.Duration(jitterAmount*1000)*time.Millisecond)

		resp, err = action(&matcher.HTTPClient)

		// Don't retry, since deadline has already been exceeded
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		// The network request itself failed, did not even get a response
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: request failed: %w", i+1, err)
			continue
		}

		// Everything is fine, including 404 which is one of the expected results
		if resp.StatusCode >= 200 && resp.StatusCode < 300 || resp.StatusCode == http.StatusNotFound {
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

func (matcher *DepsDevBaseImageMatcher) queryBaseImagesForChainID(ctx context.Context, chainID digest.Digest) ([]models.BaseImageDetails, error) {
	resp, err := matcher.makeRetryRequest(func(client *http.Client) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIEndpoint+chainID.String(), nil)
		if err != nil {
			// This error should be impossible
			return nil, err
		}

		if matcher.Config.UserAgent != "" {
			req.Header.Set("User-Agent", matcher.Config.UserAgent)
		}

		return client.Do(req)
	})

	if err != nil {
		cmdlogger.Errorf("deps.dev API error, you may need to update osv-scanner: %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var results struct {
		Results []struct {
			Repository string `json:"repository"`
		} `json:"results"`
	}

	d := json.NewDecoder(resp.Body)
	err = d.Decode(&results)
	if err != nil {
		cmdlogger.Errorf("Unexpected return type from deps.dev base image endpoint: %s", err)
		return nil, err
	}

	// Found some base images!
	baseImagePossibilities := []models.BaseImageDetails{}
	for _, r := range results.Results {
		baseImagePossibilities = append(baseImagePossibilities, models.BaseImageDetails{
			Name: r.Repository,
		})
	}

	// TODO(v2): Temporary heuristic for what is more popular
	// Ideally this is done by deps.dev before release
	slices.SortFunc(baseImagePossibilities, func(a, b models.BaseImageDetails) int {
		lengthDiff := len(a.Name) - len(b.Name)
		if lengthDiff != 0 {
			return lengthDiff
		}

		// Apply deterministic ordering to same length base images
		return strings.Compare(a.Name, b.Name)
	})

	return baseImagePossibilities, nil
}

func buildBaseImageDetails(layerMetadata []models.LayerMetadata, baseImagesToLayersMap [][]models.BaseImageDetails) [][]models.BaseImageDetails {
	allBaseImages := [][]models.BaseImageDetails{
		// The base image at index 0 is a placeholder representing your image, so always empty
		// This is the case even if your image is a base image, in that case no layers point to index 0
		{},
	}

	currentBaseImageIndex := 0
	for i, baseImages := range slices.Backward(baseImagesToLayersMap) {
		if len(baseImages) == 0 {
			layerMetadata[i].BaseImageIndex = currentBaseImageIndex
			continue
		}

		// Is the current set of baseImages the same as the previous?
		if cmp.Equal(baseImages, allBaseImages[len(allBaseImages)-1]) {
			// If so, merge them
			layerMetadata[i].BaseImageIndex = currentBaseImageIndex
			continue
		}

		// This layer is a new base image boundary
		allBaseImages = append(allBaseImages, baseImages)
		currentBaseImageIndex += 1
		layerMetadata[i].BaseImageIndex = currentBaseImageIndex
	}

	return allBaseImages
}
