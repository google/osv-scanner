package osvdev_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestOSVClient_GetVulnsByID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		id              string
		wantErrContains string
	}{
		{
			name: "Simple ID lookup",
			id:   "GO-2024-3333",
		},
		{
			name:            "Missing ID lookup",
			id:              "GO-1000-1000",
			wantErrContains: `client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`,
		},
		{
			name:            "Invalid ID",
			id:              "_--_--",
			wantErrContains: `client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"
			got, err := c.GetVulnsByID(context.Background(), tt.id)
			if err != nil {
				if tt.wantErrContains == "" || !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("OSVClient.GetVulnsByID() error = %v, wantErr %q", err, tt.wantErrContains)
				}
				return
			}
			if got.ID != tt.id {
				t.Errorf("OSVClient.GetVulnsByID() = %v, want %v", got, tt.id)
			}
		})
	}
}

func TestOSVClient_QueryBatch(t *testing.T) {
	tests := []struct {
		name            string
		queries         []*osvdev.Query
		wantIDs         [][]string
		wantErrContains string
	}{
		{
			name: "multiple queries lookup",
			queries: []*osvdev.Query{
				{
					Package: osvdev.Package{
						Name:      "faker",
						Ecosystem: string(osvschema.EcosystemNPM),
					},
					Version: "6.6.6",
				},
				{
					Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
				},
				{
					Package: osvdev.Package{
						Name:      "abcd-definitely-does-not-exist",
						Ecosystem: string(osvschema.EcosystemNPM),
					},
					Version: "1.0.0",
				},
			},
			wantIDs: [][]string{
				{ // Package Query
					"GHSA-5w9c-rv96-fr7g",
				},
				{ // Commit
					"OSV-2023-890",
				},
				// non-existent package
				{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"
			got, err := c.QueryBatch(context.Background(), tt.queries)
			if err != nil {
				if tt.wantErrContains == "" || !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("OSVClient.GetVulnsByID() error = %v, wantErr %q", err, tt.wantErrContains)
				}
				return
			}

			gotResults := make([][]string, 0, len(got.Results))
			for _, res := range got.Results {
				gotVulnIDs := make([]string, 0, len(res.Vulns))
				for _, vuln := range res.Vulns {
					gotVulnIDs = append(gotVulnIDs, vuln.ID)
				}
				gotResults = append(gotResults, gotVulnIDs)
			}

			if diff := cmp.Diff(tt.wantIDs, gotResults); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOSVClient_Query(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		query           osvdev.Query
		wantIDs         []string
		wantErrContains string
	}{
		{
			name: "npm Package lookup",
			query: osvdev.Query{
				Package: osvdev.Package{
					// Use a deleted package as it is less likely new vulns will be published for it
					Name:      "faker",
					Ecosystem: string(osvschema.EcosystemNPM),
				},
				Version: "6.6.6",
			},
			wantIDs: []string{
				"GHSA-5w9c-rv96-fr7g",
			},
		},
		{
			name: "commit lookup",
			query: osvdev.Query{
				Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
			},
			wantIDs: []string{
				"OSV-2023-890",
			},
		},
		{
			name: "unknown package lookup",
			query: osvdev.Query{
				Package: osvdev.Package{
					Name:      "abcd-definitely-does-not-exist",
					Ecosystem: string(osvschema.EcosystemNPM),
				},
				Version: "1.0.0",
			},
			wantIDs: []string{},
		},
		{
			name: "invalid query",
			query: osvdev.Query{
				Package: osvdev.Package{
					Name: "abcd-definitely-does-not-exist",
				},
			},
			wantErrContains: `client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"
			got, err := c.Query(context.Background(), &tt.query)
			if err != nil {
				if tt.wantErrContains == "" || !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("OSVClient.GetVulnsByID() error = %v, wantErr %q", err, tt.wantErrContains)
				}
				return
			}

			gotVulnIDs := make([]string, 0, len(got.Vulns))
			for _, vuln := range got.Vulns {
				gotVulnIDs = append(gotVulnIDs, vuln.ID)
			}

			if diff := cmp.Diff(tt.wantIDs, gotVulnIDs); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOSVClient_ExperimentalDetermineVersion(t *testing.T) {
	// TODO
}
