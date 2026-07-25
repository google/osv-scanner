package osvmatcher

import (
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"osv.dev/bindings/go/api"
	"osv.dev/bindings/go/osvdev"
)

func TestDryRunMatcher_MatchVulnerabilities(t *testing.T) {
	t.Parallel()

	matcher := &DryRunMatcher{}
	pkgs := []*extractor.Package{
		{Name: "a", Version: "1.0.0", PURLType: purl.TypeNPM},
		{Name: "a", Version: "1.0.0", PURLType: purl.TypeNPM}, // duplicate should be deduped in payload
		{Name: "b", Version: "2.0.0", PURLType: purl.TypeNPM},
	}

	got, err := matcher.MatchVulnerabilities(t.Context(), pkgs)
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}
	if len(got) != len(pkgs) {
		t.Fatalf("result length = %d, want %d", len(got), len(pkgs))
	}
	for i, vulns := range got {
		if len(vulns) != 0 {
			t.Fatalf("result[%d] = %#v, want empty", i, vulns)
		}
	}
}

func TestDryRunMatcher_MatchVulnerabilities_NoPackages(t *testing.T) {
	t.Parallel()

	matcher := &DryRunMatcher{}
	got, err := matcher.MatchVulnerabilities(t.Context(), nil)
	if err != nil {
		t.Fatalf("MatchVulnerabilities() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("result length = %d, want 0", len(got))
	}
}

func TestMarshalBatchQuery(t *testing.T) {
	t.Parallel()

	queries, _ := pkgsToUniqueQueries([]*extractor.Package{
		{Name: "a", Version: "1.0.0", PURLType: purl.TypeNPM},
		{Name: "a", Version: "1.0.0", PURLType: purl.TypeNPM},
		{Name: "b", Version: "2.0.0", PURLType: purl.TypeNPM},
	})
	queries = filterNilQueries(queries)

	body, err := marshalBatchQuery(queries)
	if err != nil {
		t.Fatalf("marshalBatchQuery() error = %v", err)
	}

	// protojson Multiline may insert extra spaces after colons; match flexibly.
	if !strings.Contains(body, `"a"`) || !strings.Contains(body, `"b"`) {
		t.Fatalf("expected package names in payload, got:\n%s", body)
	}
	if strings.Count(body, `"a"`) != 1 {
		t.Fatalf("expected package a to appear once after dedupe, got:\n%s", body)
	}
	if !strings.Contains(body, `"npm"`) {
		t.Fatalf("expected ecosystem in payload, got:\n%s", body)
	}

	// Sanity-check the URL constants we surface to users still match the client.
	if osvdev.DefaultBaseURL+osvdev.QueryBatchEndpoint != "https://api.osv.dev/v1/querybatch" {
		t.Fatalf("unexpected querybatch URL: %s%s", osvdev.DefaultBaseURL, osvdev.QueryBatchEndpoint)
	}
}

func TestFilterNilQueries(t *testing.T) {
	t.Parallel()

	got := filterNilQueries([]*api.Query{
		nil,
		{Param: &api.Query_Version{Version: "1.0.0"}},
		nil,
	})
	if len(got) != 1 {
		t.Fatalf("filterNilQueries() len = %d, want 1", len(got))
	}
}
