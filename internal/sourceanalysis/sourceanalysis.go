package sourceanalysis

import (
	"fmt"
	"path/filepath"

	"golang.org/x/exp/slices"
	"golang.org/x/vuln/exp/govulncheck"

	"github.com/google/osv-scanner/internal/govulncheckshim"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type MatchedVulnerability struct {
	vuln  models.Vulnerability
	group *models.GroupInfo
	pkg   models.PackageInfo
}

// vulnsFromAllPkgs returns the flattened list of unique vulnerabilities
func vulnsFromAllPkgs(pkgs []models.PackageVulns) []models.Vulnerability {
	flatVulns := map[string]models.Vulnerability{}
	for _, pv := range pkgs {
		for _, vuln := range pv.Vulnerabilities {
			flatVulns[vuln.ID] = vuln
		}
	}

	vulnList := []models.Vulnerability{}
	for _, v := range flatVulns {
		vulnList = append(vulnList, v)
	}

	return vulnList
}

// Run runs the language specific analyzers on the code given packages and source info
func Run(r *output.Reporter, source models.SourceInfo, pkgs []models.PackageVulns) {
	vulnsSlice := vulnsFromAllPkgs(pkgs)

	// GoVulnCheck
	if source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" {
		res, err := govulncheckshim.RunGoVulnCheck(filepath.Dir(source.Path), vulnsSlice)
		if err != nil {
			// TODO: Better method to identify the type of error and give advice specific to the error
			r.PrintError(
				fmt.Sprintf("Failed to run code analysis (govulncheck) on '%s' because %s\n"+
					"(the Go toolchain is required)\n", source.Path, err.Error()))

			return
		}
		gvcResByVulnID := map[string]*govulncheck.Vuln{}
		for _, v := range res.Vulns {
			gvcResByVulnID[v.OSV.ID] = v
		}

		for _, pv := range pkgs {
			// Use index to keep reference to original element in slice
			for groupIdx := range pv.Groups {
				for _, vulnID := range pv.Groups[groupIdx].IDs {
					gvcVuln, ok := gvcResByVulnID[vulnID]
					if !ok {
						continue
					}
					containsModule := slices.ContainsFunc(gvcVuln.Modules, func(module *govulncheck.Module) bool {
						return module.Path == pv.Package.Name
					})
					analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
					if *analysis == nil {
						*analysis = make(map[string]models.AnalysisInfo)
					}

					if !containsModule {
						// Code does not import module, so definitely not called
						(*analysis)[vulnID] = models.AnalysisInfo{
							Called: false,
						}
					} else {
						// Codes does import module, check if it's called
						(*analysis)[vulnID] = models.AnalysisInfo{
							Called: gvcVuln.IsCalled(),
						}
					}
				}
			}
		}
	}
}
