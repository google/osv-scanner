package baseimagematcher

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/opencontainers/go-digest"
)

const (
	maxConcurrentRequests = 1000
)

// OSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every package version and does not perform caching.
type DepsDevBaseImageMatcher struct {
	Client http.Client
}

func (matcher *DepsDevBaseImageMatcher) MatchBaseImages(ctx context.Context, layerMetadata []models.LayerMetadata) ([][]models.BaseImageDetails, error) {
	var runningDigest digest.Digest
	baseImages := [][]models.BaseImageDetails{
		// The base image at index 0 is a placeholder representing your image, so always empty
		// This is the case even if your image is a base image, in that case no layers point to index 0
		{},
	}

	chainIDs := []digest.Digest{}

	for _, l := range layerMetadata {
		if l.DiffID == "" {
			chainIDs = append(chainIDs, "")
			continue
		}

		if runningDigest == "" {
			runningDigest = l.DiffID
		} else {
			runningDigest = digest.FromBytes([]byte(runningDigest + " " + l.DiffID))
		}

		chainIDs = append(chainIDs, runningDigest)
	}

	currentBaseImageIndex := 0
	for i, cid := range slices.Backward(chainIDs) {
		if cid == "" {
			layerMetadata[i].BaseImageIndex = currentBaseImageIndex
			continue
		}

		resp, err := matcher.Client.Get("https://api.deps.dev/v3alpha/querycontainerimages/" + cid.String())
		if err != nil {
			log.Errorf("API DEPS DEV ERROR: %s", err)
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			layerMetadata[i].BaseImageIndex = currentBaseImageIndex
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Errorf("API DEPS DEV ERROR: %s", resp.Status)
			continue
		}

		d := json.NewDecoder(resp.Body)

		type baseImageEntry struct {
			Repository string `json:"repository"`
		}
		type baseImageResults struct {
			Results []baseImageEntry `json:"results"`
		}

		var results baseImageResults
		err = d.Decode(&results)
		if err != nil {
			log.Errorf("API DEPS DEV ERROR: %s", err)
			continue
		}

		// Found some base images!
		baseImagePossibilities := []models.BaseImageDetails{}
		for _, r := range results.Results {
			baseImagePossibilities = append(baseImagePossibilities, models.BaseImageDetails{
				Name: r.Repository,
			})
		}

		slices.SortFunc(baseImagePossibilities, func(a, b models.BaseImageDetails) int {
			return len(a.Name) - len(b.Name)
		})

		baseImages = append(baseImages, baseImagePossibilities)
		currentBaseImageIndex += 1
		layerMetadata[i].BaseImageIndex = currentBaseImageIndex

		// Backfill with heuristic

		possibleFinalBaseImageCommands := []string{
			"/bin/sh -c #(nop)  CMD",
			"CMD",
			"/bin/sh -c #(nop)  ENTRYPOINT",
			"ENTRYPOINT",
		}
	BackfillLoop:
		for i2 := i; i2 < len(layerMetadata); i2++ {
			if !layerMetadata[i2].IsEmpty {
				break
			}
			buildCommand := layerMetadata[i2].Command
			layerMetadata[i2].BaseImageIndex = currentBaseImageIndex
			for _, prefix := range possibleFinalBaseImageCommands {
				if strings.HasPrefix(buildCommand, prefix) {
					break BackfillLoop
				}
			}
		}
	}

	return baseImages, nil

	// vulnerabilities := make([][]*models.Vulnerability, len(batchResp.Results))
	// g, ctx := errgroup.WithContext(ctx)
	// g.SetLimit(maxConcurrentRequests)

	// for batchIdx, resp := range batchResp.Results {
	// 	vulnerabilities[batchIdx] = make([]*models.Vulnerability, len(resp.Vulns))
	// 	for resultIdx, vuln := range resp.Vulns {
	// 		g.Go(func() error {
	// 			// exit early if another hydration request has already failed
	// 			// results are thrown away later, so avoid needless work
	// 			if ctx.Err() != nil {
	// 				return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
	// 			}
	// 			vuln, err := matcher.Client.GetVulnByID(ctx, vuln.ID)
	// 			if err != nil {
	// 				return err
	// 			}
	// 			vulnerabilities[batchIdx][resultIdx] = vuln

	// 			return nil
	// 		})
	// 	}
	// }

	// if err := g.Wait(); err != nil {
	// 	return nil, err
	// }

	// if deadlineExceeded {
	// 	return vulnerabilities, context.DeadlineExceeded
	// }

	// return vulnerabilities, nil
}
