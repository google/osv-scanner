package osvdev_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scanner/internal/osvdev"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestOSVClient_GetVulnsByID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{
			name: "Simple ID lookup",
			id:   "GO-2024-3333",
		},
		{
			name: "Missing ID lookup",
			id:   "GO-1000-1000",
			wantErr: extracttest.ContainsErrStr{
				Str: `client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`,
			},
		},
		{
			name: "Invalid ID",
			id:   "_--_--",
			wantErr: extracttest.ContainsErrStr{
				Str: `client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.GetVulnByID(context.Background(), tt.id)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
				return
			}

			if got.ID != tt.id {
				t.Errorf("OSVClient.GetVulnsByID() = %v, want %v", got, tt.id)
			}
		})
	}
}

func TestOSVClient_QueryBatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		queries []*osvdev.Query
		wantIDs [][]string
		wantErr error
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
		{
			name: "multiple queries with invalid",
			queries: []*osvdev.Query{
				{
					Package: osvdev.Package{
						Name:      "faker",
						Ecosystem: string(osvschema.EcosystemNPM),
					},
					Version: "6.6.6",
				},
				{
					Package: osvdev.Package{
						Name: "abcd-definitely-does-not-exist",
					},
				},
			},
			wantIDs: [][]string{},
			wantErr: extracttest.ContainsErrStr{
				Str: `client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`,
			},
		},
		// {
		// 	name: "linux package lookup",
		// 	queries: []*osvdev.Query{
		// 		{
		// 			Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
		// 		},
		// 		{
		// 			Package: osvdev.Package{
		// 				Name:      "linux",
		// 				Ecosystem: "Ubuntu:22.04:LTS",
		// 			},
		// 			Version: "5.15.0-17.17",
		// 		},
		// 		{
		// 			Package: osvdev.Package{
		// 				Name:      "abcd-definitely-does-not-exist",
		// 				Ecosystem: string(osvschema.EcosystemNPM),
		// 			},
		// 			Version: "1.0.0",
		// 		},
		// 	},
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.QueryBatch(context.Background(), tt.queries)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
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
		name    string
		query   osvdev.Query
		wantIDs []string
		wantErr error
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
			wantErr: extracttest.ContainsErrStr{
				Str: `client error: status="400 Bad Request" body={"code":3,"message":"Invalid query."}`,
			},
		},
		// {
		// 	name: "linux Package lookup",
		// 	query: osvdev.Query{
		// 		Package: osvdev.Package{
		// 			// Use a deleted package as it is less likely new vulns will be published for it
		// 			Name:      "linux",
		// 			Ecosystem: "Ubuntu:22.04:LTS",
		// 		},
		// 		Version: "5.15.0-17.17",
		// 	},
		// 	wantIDs: []string{
		// 		"GHSA-5w9c-rv96-fr7g",
		// 	},
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.Query(context.Background(), &tt.query)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("Unexpected error (-want +got):\n%s", diff)
			}

			if err != nil {
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
	t.Parallel()

	tests := []struct {
		name     string
		query    osvdev.DetermineVersionsRequest
		wantPkgs []string
	}{
		{
			name: "Simple non existent package query",
			query: osvdev.DetermineVersionsRequest{
				Name: "test file",
				FileHashes: []osvdev.DetermineVersionHash{
					{
						Path: "test file/file",
						Hash: []byte{},
					},
				},
			},
			wantPkgs: []string{},
		},
		// TODO: Add query for an actual package, this is not added at the moment as it requires too many hashes
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := osvdev.DefaultClient()
			c.Config.UserAgent = "osv-scanner-api-test"

			got, err := c.ExperimentalDetermineVersion(context.Background(), &tt.query)
			if err != nil {
				t.Fatalf("Unexpected error %v", err)
			}

			gotPkgInfo := make([]string, 0, len(got.Matches))
			for _, vuln := range got.Matches {
				gotPkgInfo = append(gotPkgInfo, vuln.RepoInfo.Address+"@"+vuln.RepoInfo.Version)
			}

			if diff := cmp.Diff(tt.wantPkgs, gotPkgInfo); diff != "" {
				t.Errorf("Unexpected vuln IDs (-want +got):\n%s", diff)
			}
		})
	}
}
