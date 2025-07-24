package ci_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/ci"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func parseTime(t *testing.T, str string) time.Time {
	t.Helper()

	ti, err := time.Parse(time.RFC3339, str)
	if err != nil {
		panic(err)
	}

	return ti
}

func TestLoadVulnResults(t *testing.T) {
	t.Parallel()

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    models.VulnerabilityResults
		wantErr bool
	}{
		{
			name:    "does_not_exist",
			args:    args{path: "./fixtures/does_not_exist"},
			want:    models.VulnerabilityResults{},
			wantErr: true,
		},
		{
			name:    "invalid_json",
			args:    args{path: "./fixtures/not-json.txt"},
			want:    models.VulnerabilityResults{},
			wantErr: true,
		},
		{
			name: "results_empty",
			args: args{path: "./fixtures/results-empty.json"},
			want: models.VulnerabilityResults{
				Results: []models.PackageSource{},
				ExperimentalAnalysisConfig: models.ExperimentalAnalysisConfig{
					Licenses: models.ExperimentalLicenseConfig{
						Summary:   true,
						Allowlist: []models.License{"MIT"},
					},
				},
				ImageMetadata:  nil,
				LicenseSummary: nil,
			},
			wantErr: false,
		},
		{
			name: "results_some",
			args: args{path: "./fixtures/results-some.json"},
			want: models.VulnerabilityResults{
				Results: []models.PackageSource{
					{
						Source: models.SourceInfo{
							Path: "/path/to/different-dir/go.mod",
							Type: "lockfile",
						},
						ExperimentalAnnotations: nil,
						Packages: []models.PackageVulns{
							{
								Package: models.PackageInfo{
									Name:      "github.com/gogo/protobuf",
									Version:   "1.3.1",
									Ecosystem: "Go",
								},
								Vulnerabilities: []osvschema.Vulnerability{
									{
										SchemaVersion: "1.4.0",
										ID:            "GO-2021-0053",
										Modified:      parseTime(t, "2023-06-12T18:45:41Z"),
										Published:     parseTime(t, "2021-04-14T20:04:52Z"),
										Aliases:       []string{"CVE-2021-3121", "GHSA-c3h9-896r-86jm"},
										Summary:       "Panic due to improper input validation in github.com/gogo/protobuf",
										Details:       "Due to improper bounds checking, maliciously crafted input to generated Unmarshal methods can cause an out-of-bounds panic. If parsing messages from untrusted parties, this may be used as a denial of service vector.",
										Affected: []osvschema.Affected{
											{
												Package: osvschema.Package{
													Ecosystem: "Go",
													Name:      "github.com/gogo/protobuf",
													Purl:      "pkg:golang/github.com/gogo/protobuf",
												},
												Ranges: []osvschema.Range{{
													Type: "SEMVER",
													Events: []osvschema.Event{
														{Introduced: "0"},
														{Fixed: "1.3.2"},
													},
												}},
												DatabaseSpecific: map[string]any{"source": "https://vuln.go.dev/ID/GO-2021-0053.json"},
												EcosystemSpecific: map[string]any{"imports": []any{map[string]any{
													"path":    "github.com/gogo/protobuf/plugin/unmarshal",
													"symbols": []any{"unmarshal.Generate", "unmarshal.field"},
												}}},
											},
										},
										References: []osvschema.Reference{
											{Type: "FIX", URL: "https://github.com/gogo/protobuf/commit/b03c65ea87cdc3521ede29f62fe3ce239267c1bc"},
										},
										DatabaseSpecific: map[string]any{"url": "https://pkg.go.dev/vuln/GO-2021-0053"},
									},
								},
								Groups:            []models.GroupInfo{{IDs: []string{"GO-2021-0053"}}},
								Licenses:          nil,
								LicenseViolations: nil,
							},
						},
					},
				},
				ExperimentalAnalysisConfig: models.ExperimentalAnalysisConfig{
					Licenses: models.ExperimentalLicenseConfig{
						Summary: true,
					},
				},
				ImageMetadata:  nil,
				LicenseSummary: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ci.LoadVulnResults(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadVulnResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("LoadVulnResults() returned unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
