package ci_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/ci"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	tests := []struct {
		name    string
		path    string
		want    models.VulnerabilityResults
		wantErr bool
	}{
		{
			name:    "does_not_exist",
			path:    "./testdata/does_not_exist",
			want:    models.VulnerabilityResults{},
			wantErr: true,
		},
		{
			name:    "invalid_json",
			path:    "./testdata/not-json.txt",
			want:    models.VulnerabilityResults{},
			wantErr: true,
		},
		{
			name: "results_empty",
			path: "./testdata/results-empty.json",
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
			path: "./testdata/results-some.json",
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
								Vulnerabilities: []*osvschema.Vulnerability{
									{
										SchemaVersion: "1.4.0",
										Id:            "GO-2021-0053",
										Modified:      timestamppb.New(parseTime(t, "2023-06-12T18:45:41Z")),
										Published:     timestamppb.New(parseTime(t, "2021-04-14T20:04:52Z")),
										Aliases:       []string{"CVE-2021-3121", "GHSA-c3h9-896r-86jm"},
										Summary:       "Panic due to improper input validation in github.com/gogo/protobuf",
										Details:       "Due to improper bounds checking, maliciously crafted input to generated Unmarshal methods can cause an out-of-bounds panic. If parsing messages from untrusted parties, this may be used as a denial of service vector.",
										Affected: []*osvschema.Affected{
											{
												Package: &osvschema.Package{
													Ecosystem: "Go",
													Name:      "github.com/gogo/protobuf",
													Purl:      "pkg:golang/github.com/gogo/protobuf",
												},
												Ranges: []*osvschema.Range{{
													Type: osvschema.Range_SEMVER,
													Events: []*osvschema.Event{
														{Introduced: "0"},
														{Fixed: "1.3.2"},
													},
												}},
												DatabaseSpecific: &structpb.Struct{
													Fields: map[string]*structpb.Value{
														"source": {
															Kind: &structpb.Value_StringValue{
																StringValue: "https://vuln.go.dev/ID/GO-2021-0053.json",
															},
														},
													},
												},
												EcosystemSpecific: &structpb.Struct{
													Fields: map[string]*structpb.Value{
														"imports": {
															Kind: &structpb.Value_ListValue{
																ListValue: &structpb.ListValue{
																	Values: []*structpb.Value{
																		{
																			Kind: &structpb.Value_StructValue{
																				StructValue: &structpb.Struct{
																					Fields: map[string]*structpb.Value{
																						"path": {
																							Kind: &structpb.Value_StringValue{
																								StringValue: "github.com/gogo/protobuf/plugin/unmarshal",
																							},
																						},
																						"symbols": {
																							Kind: &structpb.Value_ListValue{
																								ListValue: &structpb.ListValue{
																									Values: []*structpb.Value{
																										{
																											Kind: &structpb.Value_StringValue{
																												StringValue: "unmarshal.Generate",
																											},
																										},
																										{
																											Kind: &structpb.Value_StringValue{
																												StringValue: "unmarshal.field",
																											},
																										},
																									},
																								},
																							},
																						},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
										References: []*osvschema.Reference{
											{Type: osvschema.Reference_FIX, Url: "https://github.com/gogo/protobuf/commit/b03c65ea87cdc3521ede29f62fe3ce239267c1bc"},
										},
										DatabaseSpecific: &structpb.Struct{
											Fields: map[string]*structpb.Value{
												"url": {
													Kind: &structpb.Value_StringValue{
														StringValue: "https://pkg.go.dev/vuln/GO-2021-0053",
													},
												},
											},
										},
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

			got, err := ci.LoadVulnResults(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadVulnResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("LoadVulnResults() returned unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
