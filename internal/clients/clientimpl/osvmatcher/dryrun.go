package osvmatcher

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

// DryRunMatcher implements VulnerabilityMatcher by printing the OSV.dev requests
// that would be made without sending them over the network.
//
// This is intended for privacy-conscious users who want to inspect what package
// names, versions, ecosystems, and commits would be shared with OSV.dev.
type DryRunMatcher struct{}

// MatchVulnerabilities builds the querybatch payload that would be sent to OSV.dev,
// prints it, and returns empty vulnerability results for every package.
func (matcher *DryRunMatcher) MatchVulnerabilities(_ context.Context, pkgs []*extractor.Package) ([][]*osvschema.Vulnerability, error) {
	queries, _ := pkgsToUniqueQueries(pkgs)
	queries = filterNilQueries(queries)

	cmdlogger.Infof("Dry-run mode: no requests will be sent to OSV.dev")
	cmdlogger.Infof("The following request would be sent to OSV.dev:")
	cmdlogger.Infof("POST %s%s", osvdev.DefaultBaseURL, osvdev.QueryBatchEndpoint)

	if len(queries) == 0 {
		cmdlogger.Infof("(no package queries would be sent)")
	} else {
		body, err := marshalBatchQuery(queries)
		if err != nil {
			return nil, fmt.Errorf("failed to encode dry-run querybatch payload: %w", err)
		}
		// Log each line separately so cmdlogger formatting stays readable.
		for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
			cmdlogger.Infof("%s", line)
		}
	}

	cmdlogger.Infof(
		"If vulnerabilities were returned, follow-up GET %s%s/{id} requests would be made for each vulnerability ID",
		osvdev.DefaultBaseURL,
		osvdev.GetEndpoint,
	)
	cmdlogger.Infof(
		"Vendored C/C++ determineversion requests to %s%s are also skipped in dry-run mode",
		osvdev.DefaultBaseURL,
		osvdev.DetermineVersionEndpoint,
	)

	// Return empty results matching the original package list length.
	results := make([][]*osvschema.Vulnerability, len(pkgs))
	for i := range results {
		results[i] = []*osvschema.Vulnerability{}
	}

	return results, nil
}

func filterNilQueries(queries []*api.Query) []*api.Query {
	filtered := make([]*api.Query, 0, len(queries))
	for _, q := range queries {
		if q != nil {
			filtered = append(filtered, q)
		}
	}

	return filtered
}

func marshalBatchQuery(queries []*api.Query) (string, error) {
	batch := &api.BatchQuery{Queries: queries}
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
	}

	body, err := opts.Marshal(batch)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
