package output_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type outputTestCaseArgs struct {
	vulnResult *models.VulnerabilityResults
}

type outputTestCase struct {
	name string
	args outputTestCaseArgs
}

type outputTestRunner = func(t *testing.T, args outputTestCaseArgs)

type pkginfo struct {
	Name          string
	OSPackageName string
	Version       string
	Ecosystem     string
	Commit        string
	ImageOrigin   *models.ImageOriginDetails
	Extractor     extractor.Extractor
}

func newPackageInfo(source string, pi pkginfo) models.PackageInfo {
	info := models.PackageInfo{
		Name:          pi.Name,
		OSPackageName: pi.OSPackageName,
		Version:       pi.Version,
		Ecosystem:     pi.Ecosystem,
		Commit:        pi.Commit,
		ImageOrigin:   pi.ImageOrigin,
		Inventory: &extractor.Inventory{
			Name:      pi.Name,
			Version:   pi.Version,
			Extractor: pi.Extractor,
			Locations: []string{source},
		},
	}

	return info
}

func testOutputWithVulnerabilities(t *testing.T, run outputTestRunner) {
	t.Helper()

	tests := []outputTestCase{
		{
			name: "no sources",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{},
				},
			},
		},
		{
			name: "one source with no packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "multiple sources with no packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "one source with one package, no vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple sources with a mixed count of packages, no vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "one source with one package and one vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package and one called vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-1"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: true},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package and one uncalled vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-1"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: false},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package, one uncalled vulnerability, and one called vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "GHSA-123",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package and one vulnerability (dev)",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Groups:    []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "two sources with the same vulnerable package",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Groups:    []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package and two aliases of a single vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs:     []string{"OSV-1", "GHSA-123"},
										Aliases: []string{"OSV-1", "GHSA-123"},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "GHSA-123",
											Summary:  "Something scary!",
											Aliases:  []string{"OSV-1"},
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package and two aliases of a single uncalled vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs:     []string{"OSV-1", "GHSA-123"},
										Aliases: []string{"OSV-1", "GHSA-123"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: false},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "GHSA-123",
											Summary:  "Something scary!",
											Aliases:  []string{"OSV-1"},
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "two sources with packages, one vulnerability",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "5.9.0",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple sources with a mixed count of packages, some vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities: []osvschema.Vulnerability{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "multiple sources with a mixed count of packages, and multiple vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{
										{IDs: []string{"OSV-1"}},
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{
										{IDs: []string{"OSV-3"}},
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []osvschema.Severity{{Type: "medium", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
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
			name: "multiple sources with a mixed count of grouped packages, and multiple vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev", "optional"},
									Groups: []models.GroupInfo{
										{IDs: []string{"OSV-1"}},
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Groups:    []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"build"},
									Groups: []models.GroupInfo{
										{IDs: []string{"OSV-3"}},
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []osvschema.Severity{{Type: "medium", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
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
			name: "multiple sources with a mixed count of packages across ecosystems, and multiple vulnerabilities",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "author1/mine1",
										Version:   "1.2.3",
										Ecosystem: "Packagist",
										Extractor: composerlock.Extractor{},
									}),
									Groups: []models.GroupInfo{
										{IDs: []string{"OSV-1"}},
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "NuGet",
										Extractor: dotnetpe.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Groups:    []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "author3/mine3",
										Version:   "0.4.1",
										Ecosystem: "Packagist",
										Extractor: packagelockjson.Extractor{},
									}),
									DepGroups: []string{"build"},
									Groups: []models.GroupInfo{
										{IDs: []string{"OSV-3"}},
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []osvschema.Severity{{Type: "medium", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
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
			name: "multiple sources with a mixed count of packages across ecosystems, and multiple vulnerabilities, but some uncalled",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.2",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "NuGet",
										Extractor: dotnetpe.Extractor{},
									}),
									DepGroups: []string{"dev"},
									Groups:    []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
										{IDs: []string{"OSV-5"}},
									},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-3",
											Summary:  "Something mildly scary!",
											Severity: []osvschema.Severity{{Type: "medium", Score: "1"}},
										},
										{
											ID:       "OSV-5",
											Summary:  "Something scarier!",
											Severity: []osvschema.Severity{{Type: "extreme", Score: "1"}},
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
			name: "one source with vulnerabilities, some missing content",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{ID: "OSV-1", Details: "This vulnerability allows for some very scary stuff to happen - seriously, you'd not believe it!"},
									},
								},
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.10.2-rc",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{ID: "OSV-2"},
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

			run(t, tt.args)
		})
	}
}

func testOutputWithLicenseViolations(t *testing.T, run outputTestRunner) {
	t.Helper()

	experimentalAnalysisConfig := models.ExperimentalAnalysisConfig{
		Licenses: models.ExperimentalLicenseConfig{Summary: false, Allowlist: []models.License{"ISC"}},
	}

	tests := []outputTestCase{
		{
			name: "no sources",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results:                    []models.PackageSource{},
				},
			},
		},
		{
			name: "one source with no packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "multiple sources with no packages",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source:   models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{},
						},
						{
							Source:   models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{},
						},
					},
				},
			},
		},
		{
			name: "one source with one package, no licenses",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
			name: "one source with one package and an unknown license",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
			name: "one source with one package, no license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
			name: "multiple sources with a mixed count of packages, no license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
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
			name: "one source with one package and one license violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
			name: "one source with one package and one license violation (dev)",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
			name: "two sources with packages, one license violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
			name: "multiple sources with a mixed count of packages, some license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
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
			name: "multiple sources with a mixed count of packages and groups, some license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
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
			name: "multiple sources with a mixed count of packages across ecosystems, some license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{"Apache-2.0"},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "NuGet",
										Extractor: packageslockjson.Extractor{},
									}),
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
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
			name: "one source with one package and multiple license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
			name: "multiple sources with a mixed count of packages, some license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"UNKNOWN"},
									LicenseViolations: []models.License{"UNKNOWN"},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
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
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Licenses:          []models.License{"Apache-2.0"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
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

			run(t, tt.args)
		})
	}
}

func testOutputWithMixedIssues(t *testing.T, run outputTestRunner) {
	t.Helper()

	experimentalAnalysisConfig := models.ExperimentalAnalysisConfig{
		Licenses: models.ExperimentalLicenseConfig{Summary: false, Allowlist: []models.License{"ISC"}},
	}

	tests := []outputTestCase{
		{
			name: "one source with one package, one vulnerability, and one license violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package, one called vulnerability, and one license violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-1"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: true},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "one source with one package, one uncalled vulnerability, and one license violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-1"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: false},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "two sources with packages, one vulnerability, one license violation",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "5.9.0",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups:            []models.GroupInfo{},
									Vulnerabilities:   []osvschema.Vulnerability{},
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
			name: "multiple sources with a mixed count of packages, some vulnerabilities and license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-2"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []osvschema.Vulnerability{},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []osvschema.Vulnerability{},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{IDs: []string{"OSV-1"}}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
			name: "multiple sources with a mixed count of packages, some called vulnerabilities and license violations",
			args: outputTestCaseArgs{
				vulnResult: &models.VulnerabilityResults{
					ExperimentalAnalysisConfig: experimentalAnalysisConfig,
					Results: []models.PackageSource{
						{
							Source: models.SourceInfo{Path: "path/to/my/first/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/first/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-1"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: false},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
										},
									},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/second/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine2",
										Version:   "3.2.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-2"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-2": {Called: true},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-2",
											Summary:  "Something less scary!",
											Severity: []osvschema.Severity{{Type: "low", Score: "1"}},
										},
									},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
								{
									Package: newPackageInfo("path/to/my/second/lockfile", pkginfo{
										Name:      "mine3",
										Version:   "0.4.1",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []osvschema.Vulnerability{},
									Licenses:          []models.License{"ISC"},
									LicenseViolations: []models.License{},
								},
							},
						},
						{
							Source: models.SourceInfo{Path: "path/to/my/third/lockfile"},
							Packages: []models.PackageVulns{
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.3.5",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Vulnerabilities:   []osvschema.Vulnerability{},
									Licenses:          []models.License{"MIT"},
									LicenseViolations: []models.License{"MIT"},
								},
								{
									Package: newPackageInfo("path/to/my/third/lockfile", pkginfo{
										Name:      "mine1",
										Version:   "1.2.3",
										Ecosystem: "npm",
										Extractor: packagelockjson.Extractor{},
									}),
									Groups: []models.GroupInfo{{
										IDs: []string{"OSV-1"},
										ExperimentalAnalysis: map[string]models.AnalysisInfo{
											"OSV-1": {Called: false},
										},
									}},
									Vulnerabilities: []osvschema.Vulnerability{
										{
											ID:       "OSV-1",
											Summary:  "Something scary!",
											Severity: []osvschema.Severity{{Type: "high", Score: "1"}},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			run(t, tt.args)
		})
	}
}
