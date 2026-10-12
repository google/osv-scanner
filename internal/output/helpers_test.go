package output_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/java"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

type outputTestCaseArgs struct {
	vulnResult *models.VulnerabilityResults
}

type outputTestCase struct {
	name string
	// whether the groups should be built with exploitability signals, as when
	// performing call analysis
	considerExploitabilitySignals bool

	args outputTestCaseArgs
}

type outputTestRunner = func(t *testing.T, args outputTestCaseArgs)

type pkginfo struct {
	Name          string
	OSPackageName string
	Version       string
	Ecosystem     string
	Deprecated    bool
	Commit        string
	ImageOrigin   *models.ImageOriginDetails
	Extractor     extractor.Extractor
	// Uncalled marks the package as having code that is not in the execute path,
	// as would be done by call analysis
	Uncalled bool
}

func resolvePURLType(eco string) string {
	// strip any release, such as "Debian:12"
	eco, _, _ = strings.Cut(eco, ":")

	switch eco {
	case "Debian", "Ubuntu":
		return purl.TypeDebian
	case "npm":
		return purl.TypeNPM
	case "NuGet":
		return purl.TypeNuget
	case "Packagist":
		return purl.TypeComposer
	}

	panic("unknown PURL type for ecosystem " + eco)
}

func newEcosystemSpecific(fields map[string]any) *structpb.Struct {
	es, err := structpb.NewStruct(fields)
	if err != nil {
		panic(err)
	}

	return es
}

func newPackageInfo(source string, pi pkginfo) models.PackageInfo {
	info := models.PackageInfo{
		Name:          pi.Name,
		OSPackageName: pi.OSPackageName,
		Version:       pi.Version,
		Ecosystem:     pi.Ecosystem,
		Commit:        pi.Commit,
		ImageOrigin:   pi.ImageOrigin,
		Deprecated:    pi.Deprecated,
		Inventory: &extractor.Package{
			Name:     pi.Name,
			Version:  pi.Version,
			Plugins:  []string{pi.Extractor.Name()},
			Location: extractor.LocationFromPath(source),
			PURLType: resolvePURLType(pi.Ecosystem),
		},
	}

	if pi.Uncalled {
		info.Inventory.ExploitabilitySignals = []*vex.PackageExploitabilitySignal{{
			Plugin:          java.Name,
			Justification:   vex.VulnerableCodeNotInExecutePath,
			MatchesAllVulns: true,
		}}
	}

	return info
}

// buildGroups builds the groups for each package the same way the scanner does,
// preserving any analysis declared by the fixture's own groups since that
// cannot be derived from the vulnerabilities alone
func buildGroups(vulnResult *models.VulnerabilityResults, considerExploitabilitySignals bool) {
	for _, result := range vulnResult.Results {
		for j := range result.Packages {
			groups := grouper.Build(result.Packages[j], considerExploitabilitySignals)
			grouper.CopyAnalysis(result.Packages[j].Groups, groups)

			result.Packages[j].Groups = groups
		}
	}
}

func testOutputWithVulnerabilities(t *testing.T, run outputTestRunner) {
	t.Helper()

	cwd := filepath.ToSlash(testutility.GetCurrentWorkingDirectory(t))

	tests := []outputTestCase{
		{
			name: "no_sources",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{},
				},
			},
		},
		{
			name: "one_source_with_no_packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_no_packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package,_no_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_no_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_one_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{
												{
													Type:  osvschema.Severity_CVSS_V3,
													Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
												},
												{
													Type:  osvschema.Severity_Ubuntu,
													Score: "medium",
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
		{
			name: "one_source_with_one_package,_one_vulnerability,_and_a_max_severity",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_with_both_a_version_and_commit_and_one_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Commit:    "abc123",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_with_just_a_commit_and_one_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Ecosystem: "npm",
										Commit:    "abc123",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			considerExploitabilitySignals: true,

			name: "one_source_with_one_package_and_one_called_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V2,
												Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			considerExploitabilitySignals: true,

			name: "one_source_with_one_package_and_one_uncalled_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
										Uncalled:  true,
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package,_one_uncalled_vulnerability,_and_one_called_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{
										{
											IDs: []string{"OSV-1"},
											ExperimentalAnalysis: map[string]models.AnalysisInfo{
												"OSV-1": {Called: true},
											},
										},
										{
											IDs: []string{"GHSA-123"},
											ExperimentalAnalysis: map[string]models.AnalysisInfo{
												"GHSA-123": {Called: false},
											},
										},
									},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "GHSA-123",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_one_vulnerability_(dev)",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{
												{
													Type:  osvschema.Severity_CVSS_V4,
													Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
												},
												{
													Type:  osvschema.Severity_Ubuntu,
													Score: "high",
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
		{
			name: "two_sources_with_the_same_vulnerable_package",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_two_aliases_of_a_single_vulnerability_without_a_max_severity",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_Ubuntu,
												Score: "negligible",
											}},
										},
										{
											Id:      "GHSA-123",
											Summary: "Something scary!",
											Aliases: []string{"OSV-1"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_two_aliases_of_a_single_vulnerability_with_a_max_severity",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
											}},
										},
										{
											Id:      "GHSA-123",
											Summary: "Something scary!",
											Aliases: []string{"OSV-1"},
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			considerExploitabilitySignals: true,

			name: "one_source_with_one_package_and_two_aliases_of_a_single_uncalled_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
										Uncalled:  true,
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "GHSA-123",
											Summary:  "Something scary!",
											Aliases:  []string{"OSV-1"},
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "two_sources_with_packages,_one_vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{
												{
													Type:  osvschema.Severity_CVSS_V3,
													Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
												},
												{
													Type:  osvschema.Severity_CVSS_V4,
													Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
												},
											},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "5.9.0",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_some_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_and_multiple_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-2",
											Summary: "Something less scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_Ubuntu,
												Score: "high",
											}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-3",
											Summary: "Something mildly scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
											}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_grouped_packages,_and_multiple_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev", "optional"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"build"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages_across_ecosystems,_and_multiple_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "author1/mine1",
										Version:   "1.2.3",
										Ecosystem: "Packagist",
										Extractor: composerlock.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "NuGet",
										Extractor: dotnetpe.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "author3/mine3",
										Version:   "0.4.1",
										Ecosystem: "Packagist",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"build"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-3",
											Summary: "Something mildly scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
											}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages_across_ecosystems_using_commits_and_version,_and_multiple_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "author1/mine1",
										Version:   "1.2.3",
										Ecosystem: "Packagist",
										Commit:    "123abc",
										Extractor: composerlock.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Ecosystem: "npm",
										Commit:    "abcxyz",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "NuGet",
										Extractor: dotnetpe.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "author3/mine3",
										Version:   "0.4.1",
										Ecosystem: "Packagist",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"build"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages_across_ecosystems,_and_multiple_vulnerabilities,_but_some_uncalled",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "author1/mine1",
										Version:   "1.2.3",
										Ecosystem: "Packagist",
										Extractor: composerlock.Extractor{},
									}),
									Groups: []models.GroupInfo{
										{
											IDs: []string{"OSV-1"},
											ExperimentalAnalysis: map[string]models.AnalysisInfo{
												"OSV-1": {Called: false},
											},
										},
										{
											IDs: []string{"OSV-5"},
											ExperimentalAnalysis: map[string]models.AnalysisInfo{
												"OSV-5": {Called: true},
											},
										},
									},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "NuGet",
										Extractor: dotnetpe.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "author3/mine3",
										Version:   "0.4.1",
										Ecosystem: "Packagist",
										Extractor: composerlock.Extractor{},
									}),
									DepGroups: []string{"build"},
									Groups: []models.GroupInfo{
										{
											IDs: []string{"OSV-3"},
											ExperimentalAnalysis: map[string]models.AnalysisInfo{
												"OSV-3": {Called: true},
											},
										},
									},
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
										{
											Id:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_vulnerabilities,_some_missing_content",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{Id: "OSV-1", Details: "This vulnerability allows for some very scary stuff to happen - seriously, you'd not believe it!"},

										// these ensure we're truncating multibyte characters properly
										{Id: "OSV-3", Details: strings.Repeat("\u754c", 61)},
										{Id: "OSV-4", Details: strings.Repeat("\u754c", 26) + " " + strings.Repeat("\u8a9e", 34)},
									},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.10.2-rc",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{Id: "OSV-2"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// the package should be fixed by the highest of the next fixed versions
			name: "one_source_with_one_package_and_multiple_vulnerabilities,_some_fixable",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Fixed in the next patch!",
											Affected: []*osvschema.Affected{
												{
													Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
													Ranges: []*osvschema.Range{{
														Type: osvschema.Range_SEMVER,
														Events: []*osvschema.Event{
															{Introduced: "1.0.0"},
															{Fixed: "1.1.5"},
															{Introduced: "1.2.0"},
															{Fixed: "1.2.4"},
														},
													}},
												},
											},
										},
										{
											Id:      "OSV-2",
											Summary: "Fixed in the next major!",
											Affected: []*osvschema.Affected{
												{
													Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
													Ranges: []*osvschema.Range{{
														Type: osvschema.Range_SEMVER,
														Events: []*osvschema.Event{
															{Introduced: "0"},
															{Fixed: "2.0.0"},
														},
													}},
												},
											},
										},
										{
											Id:      "OSV-3",
											Summary: "Not fixed yet!",
											Affected: []*osvschema.Affected{
												{
													Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
													Ranges: []*osvschema.Range{{
														Type: osvschema.Range_SEMVER,
														Events: []*osvschema.Event{
															{Introduced: "0"},
														},
													}},
												},
											},
										},
										{
											Id:      "OSV-4",
											Summary: "Only fixed for another package!",
											Affected: []*osvschema.Affected{
												{
													Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
													Ranges: []*osvschema.Range{{
														Type: osvschema.Range_SEMVER,
														Events: []*osvschema.Event{
															{Introduced: "0"},
														},
													}},
												},
												{
													Package: &osvschema.Package{Name: "mine2", Ecosystem: "npm"},
													Ranges: []*osvschema.Range{{
														Type: osvschema.Range_SEMVER,
														Events: []*osvschema.Event{
															{Introduced: "0"},
															{Fixed: "1.0.0"},
														},
													}},
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
		{
			name: "one_os_source_with_debian_and_ubuntu_packages,_some_with_unimportant_vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/var/lib/dpkg/status", Type: models.SourceTypeOSPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/var/lib/dpkg/status", pkginfo{
										Name:          "libxml2",
										OSPackageName: "libxml2",
										Version:       "2.9.14+dfsg-1.3",
										Ecosystem:     "Debian:12",
										Extractor:     dpkg.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "DEBIAN-CVE-2024-0001",
											Summary: "Something unimportant!",
											Affected: []*osvschema.Affected{{
												EcosystemSpecific: newEcosystemSpecific(map[string]any{"urgency": "unimportant"}),
											}},
										},
										{
											Id:      "DEBIAN-CVE-2024-0002",
											Summary: "Something scary!",
											Affected: []*osvschema.Affected{{
												Package: &osvschema.Package{Name: "libxml2", Ecosystem: "Debian:12"},
												Ranges: []*osvschema.Range{{
													Type: osvschema.Range_ECOSYSTEM,
													Events: []*osvschema.Event{
														{Introduced: "0"},
														{Fixed: "2.9.14+dfsg-1.3+deb12u1"},
													},
												}},
												EcosystemSpecific: newEcosystemSpecific(map[string]any{"urgency": "low"}),
											}},
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
											}},
										},
									},
								},
								{
									Package: newPackageInfo(cwd+"/var/lib/dpkg/status", pkginfo{
										Name:          "openssl",
										OSPackageName: "openssl",
										Version:       "3.0.2-0ubuntu1.15",
										Ecosystem:     "Ubuntu:22.04",
										Extractor:     dpkg.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "UBUNTU-CVE-2024-0003",
											Summary: "Something negligible!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_Ubuntu,
												Score: "negligible",
											}},
										},
										{
											Id:      "UBUNTU-CVE-2024-0004",
											Summary: "Something scary!",
											Affected: []*osvschema.Affected{{
												Package: &osvschema.Package{Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS"},
												Ranges: []*osvschema.Range{{
													Type: osvschema.Range_ECOSYSTEM,
													Events: []*osvschema.Event{
														{Introduced: "0"},
														{Fixed: "3.0.2-0ubuntu1.16"},
													},
												}},
											}},
											Severity: []*osvschema.Severity{
												{
													Type:  osvschema.Severity_CVSS_V3,
													Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
												},
												{
													Type:  osvschema.Severity_Ubuntu,
													Score: "medium",
												},
											},
										},
										{
											// older records have the priority as ecosystem specific data
											Id:      "UBUNTU-CVE-2024-0005",
											Summary: "Something else negligible!",
											Affected: []*osvschema.Affected{{
												EcosystemSpecific: newEcosystemSpecific(map[string]any{"ubuntu_priority": "negligible"}),
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// only vulnerabilities in debian-based ecosystems can be unimportant
			name: "one_source_with_one_package_and_one_vulnerability_tagged_as_unimportant_outside_of_a_debian_based_ecosystem",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Affected: []*osvschema.Affected{{
												EcosystemSpecific: newEcosystemSpecific(map[string]any{"urgency": "unimportant"}),
											}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// Source path contains \r and \n bytes that, if echoed verbatim to
			// stdout under a GitHub Actions runner, would be parsed as workflow
			// commands (::stop-commands::, ::error::, etc.). The output formats
			// must encode these bytes (for the GHA-aware text formats) or quote
			// them via the format's native escaping (for the structured formats).
			name: "one_source_with_workflow_command_injection_attempt_in_path",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "dir\r::stop-commands::T\r::error::INJECTED\n::warning::pwn/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("dir\r::stop-commands::T\r::error::INJECTED\n::warning::pwn/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{Id: "OSV-1", Summary: "Test vulnerability"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buildGroups(tt.args.vulnResult, tt.considerExploitabilitySignals)

			run(t, tt.args)
		})
	}
}

func testOutputWithLicenseViolations(t *testing.T, run outputTestRunner) {
	t.Helper()

	cwd := filepath.ToSlash(testutility.GetCurrentWorkingDirectory(t))

	experimentalAnalysisConfig := models.ExperimentalAnalysisConfig{
		Licenses: models.ExperimentalLicenseConfig{Summary: false, Allowlist: []models.License{"ISC"}},
	}

	tests := []outputTestCase{
		{
			name: "no_sources",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results:                    []models.PackageSource{},
				},
			},
		},
		{
			name: "one_source_with_no_packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_no_packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package,_no_licenses",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{},
									LicenseViolations: []models.License{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_an_unknown_license",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"UNKNOWN"},
									LicenseViolations: []models.License{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package,_no_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_no_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_with_both_a_version_and_a_commit_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Commit:    "abc123",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_with_just_a_commit_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Ecosystem: "npm",
										Commit:    "abc123",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_one_license_violation_(dev)",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups:         []string{"dev"},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "two_sources_with_packages,_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "5.9.0",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_some_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages_and_groups,_some_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups:         []string{"dev", "optional"},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups:         []string{"dev", "optional"},
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups:         []string{"build"},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages_across_ecosystems,_some_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "author1/mine1",
										Version:   "1.2.3",
										Ecosystem: "Packagist",
										Extractor: composerlock.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "NuGet",
										Extractor: packageslockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "author1/mine1",
										Version:   "1.2.3",
										Ecosystem: "Packagist",
										Extractor: composerlock.Extractor{},
									}),
									DepGroups:         []string{"dev"},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_package_and_multiple_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT", "Apache-2.0"},
									LicenseViolations: []models.License{"MIT", "Apache-2.0"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_some_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT", "Apache-2.0"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"UNKNOWN"},
									LicenseViolations: []models.License{"UNKNOWN"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buildGroups(tt.args.vulnResult, tt.considerExploitabilitySignals)

			run(t, tt.args)
		})
	}
}

func testOutputWithMixedIssues(t *testing.T, run outputTestRunner) {
	t.Helper()

	cwd := filepath.ToSlash(testutility.GetCurrentWorkingDirectory(t))

	experimentalAnalysisConfig := models.ExperimentalAnalysisConfig{
		Licenses: models.ExperimentalLicenseConfig{Summary: false, Allowlist: []models.License{"ISC"}},
	}

	tests := []outputTestCase{
		{
			name: "one_source_with_one_package,_one_vulnerability,_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_in_working_directory_with_one_package,_one_vulnerability,_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			considerExploitabilitySignals: true,

			name: "one_source_with_one_package,_one_called_vulnerability,_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			considerExploitabilitySignals: true,

			name: "one_source_with_one_package,_one_uncalled_vulnerability,_and_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
										Uncalled:  true,
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "two_sources_with_packages,_one_vulnerability,_one_license_violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "5.9.0",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages,_some_vulnerabilities_and_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple_sources_with_a_mixed_count_of_packages_with_versions_and_commits,_some_vulnerabilities_and_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Commit:    "abcxzy",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Ecosystem: "npm",
										Commit:    "abc123",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
							},
						},
					},
				},
			},
		},
		{
			considerExploitabilitySignals: true,

			name: "multiple_sources_with_a_mixed_count_of_packages,_some_called_vulnerabilities_and_license_violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/first/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
										Uncalled:  true,
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:      "OSV-1",
											Summary: "Something scary!",
											Severity: []*osvschema.Severity{{
												Type:  osvschema.Severity_CVSS_V3,
												Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
											}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/second/lockfile", Type: models.SourceTypeSBOM},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/my/third/lockfile", Type: models.SourceTypeUnknown},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []*osvschema.Vulnerability{},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
								{
									Package: newPackageInfo(cwd+"/path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
										Uncalled:  true,
									}),
									Vulnerabilities: []*osvschema.Vulnerability{
										{
											Id:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []*osvschema.Severity{{Score: "1"}},
										},
									},
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one_source_with_one_deprecated_package",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: cwd + "/path/to/lockfile", Type: models.SourceTypeProjectPackage},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo(cwd+"/path/to/lockfile", pkginfo{
										Name:       "deprecated-pkg",
										Version:    "1.0.0",
										Ecosystem:  "npm",
										Deprecated: true,
										Extractor:  packagelockjson.Extractor{},
									}),
									Vulnerabilities: []*osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buildGroups(tt.args.vulnResult, tt.considerExploitabilitySignals)

			run(t, tt.args)
		})
	}
}
