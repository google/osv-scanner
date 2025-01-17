package baseimagematcher

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
)

const (
	maxConcurrentRequests = 1000
)

// OSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every package version and does not perform caching.
type DepsDevBaseImageMatcher struct {
	Client http.Client
	r      reporter.Reporter
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
				return nil // this value doesn't matter to errgroup.Wait(), it will be ctx.Err()
			}

			resp, err := matcher.Client.Get("https://api.deps.dev/v3alpha/querycontainerimages/" + chainID.String())
			if err != nil {
				matcher.r.Errorf("deps.dev API error: %s\n", err)
				return nil
			}

			if resp.StatusCode == http.StatusNotFound {
				return nil
			}

			if resp.StatusCode != http.StatusOK {
				matcher.r.Errorf("deps.dev API error: %s\n", resp.Status)
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
				matcher.r.Errorf("Unexpected return type from deps.dev base image endpoint: %s", err)
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
