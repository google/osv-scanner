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

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
)

const (
	maxConcurrentRequests = 1000
	APIEndpoint           = "https://api.deps.dev/v3alpha/querycontainerimages/"
)

// OSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every package version and does not perform caching.
type DepsDevBaseImageMatcher struct {
	HTTPClient http.Client
	Config     ClientConfig
	Reporter   reporter.Reporter
}

func (matcher *DepsDevBaseImageMatcher) MatchBaseImages(ctx context.Context, layerMetadata []models.LayerMetadata) ([][]models.BaseImageDetails, error) {
	baseImagesMap := make([][]models.BaseImageDetails, len(layerMetadata))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	var runningDigest digest.Digest
	for i, l := range layerMetadata {
		if l.DiffID == "" {
			continue
		}

		if runningDigest == "" {
			runningDigest = l.DiffID
		} else {
			runningDigest = digest.FromBytes([]byte(runningDigest + " " + l.DiffID))
		}

		chainID := runningDigest
		g.Go(func() error {
			if ctx.Err() != nil {
				return ctx.Err() // this value doesn't matter to errgroup.Wait(), it will be ctx.Err()
			}

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
				matcher.Reporter.Errorf("deps.dev API error: %s\n", err)
				return nil
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				return nil
			}

			var results struct {
				Results []struct {
					Repository string `json:"repository"`
				} `json:"results"`
			}

			d := json.NewDecoder(resp.Body)
			err = d.Decode(&results)
			if err != nil {
				matcher.Reporter.Errorf("Unexpected return type from deps.dev base image endpoint: %s", err)
				return nil
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
				return len(a.Name) - len(b.Name)
			})
			baseImagesMap[i] = baseImagePossibilities

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, context.DeadlineExceeded
	}

	allBaseImages := [][]models.BaseImageDetails{
		// The base image at index 0 is a placeholder representing your image, so always empty
		// This is the case even if your image is a base image, in that case no layers point to index 0
		{},
	}

	currentBaseImageIndex := 0
	for i, baseImages := range slices.Backward(baseImagesMap) {
		if len(baseImages) == 0 {
			layerMetadata[i].BaseImageIndex = currentBaseImageIndex
			continue
		}

		// This layer is a base image boundary
		allBaseImages = append(allBaseImages, baseImages)
		currentBaseImageIndex += 1
		layerMetadata[i].BaseImageIndex = currentBaseImageIndex

		// Backfill with heuristic:
		//   The goal here is to replace empty layers that is currently categorized as the previous base image
		//   with this base image if it actually belongs to this layer.
		//
		//   We do this by guessing the boundary of empty layers by checking for the following commands,
		//   which are commonly the *last* layer.
		//
		//   Remember we are looping backwards in the outer loop,
		//   so this backfill is actually filling down the layer stack, not up.
		possibleFinalBaseImageCommands := []string{
			"/bin/sh -c #(nop)  CMD",
			"CMD",
			"/bin/sh -c #(nop)  ENTRYPOINT",
			"ENTRYPOINT",
		}
	BackfillLoop:
		for i2 := i; i2 < len(layerMetadata); i2++ {
			if !layerMetadata[i2].IsEmpty {
				// If the layer is not empty, whatever base image it is current assigned
				// would be already correct, we only need to adjust empty layers.
				break
			}
			buildCommand := layerMetadata[i2].Command
			layerMetadata[i2].BaseImageIndex = currentBaseImageIndex

			// Check if this is the last layer and we can stop looping
			for _, prefix := range possibleFinalBaseImageCommands {
				if strings.HasPrefix(buildCommand, prefix) {
					break BackfillLoop
				}
			}
		}
	}

	return allBaseImages, nil
}

// makeRetryRequest will return an error on both network errors, and if the response is not 200 or 404
func (c *DepsDevBaseImageMatcher) makeRetryRequest(action func(client *http.Client) (*http.Response, error)) (*http.Response, error) {
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

		resp, err = action(&c.HTTPClient)

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

	return nil, fmt.Errorf("max retries exceeded: %v", lastErr)
}
