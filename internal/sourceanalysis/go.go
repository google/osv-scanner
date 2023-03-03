package sourceanalysis

import (
	"fmt"
	"path/filepath"

	"github.com/google/osv-scanner/internal/govulncheckshim"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
	"golang.org/x/vuln/exp/govulncheck"
)

func goAnalysis(r *output.Reporter, pkgs []models.PackageVulns, source models.SourceInfo) {
	vulns, vulnsByID := vulnsFromAllPkgs(pkgs)
	res, err := govulncheckshim.RunGoVulnCheck(filepath.Dir(source.Path), vulns)
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
	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)
}

func matchAnalysisWithPackageVulns(pkgs []models.PackageVulns, gvcResByVulnID map[string]*govulncheck.Vuln, vulnsByID map[string]models.Vulnerability) {
	for _, pv := range pkgs {
		// Use index to keep reference to original element in slice
		for groupIdx := range pv.Groups {
			for _, vulnID := range pv.Groups[groupIdx].IDs {
				analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
				if *analysis == nil {
					*analysis = make(map[string]models.AnalysisInfo)
				}

				gvcVuln, ok := gvcResByVulnID[vulnID]
				if !ok { // If vulnerability not found, check if it contain any source information
					fillNotImportedAnalysisInfo(vulnsByID, vulnID, pv, analysis)
					continue
				}
				// Module list is unlikely to be very big, linear search is fine
				containsModule := slices.ContainsFunc(gvcVuln.Modules, func(module *govulncheck.Module) bool {
					return module.Path == pv.Package.Name
				})

				if !containsModule {
					// Code does not import module, so definitely not called
					(*analysis)[vulnID] = models.AnalysisInfo{
						Called: false,
					}
				} else {
					// Code does import module, check if it's called
					(*analysis)[vulnID] = models.AnalysisInfo{
						Called: gvcVuln.IsCalled(),
					}
				}
			}
		}
	}
}

// fillNotImportedAnalysisInfo checks for any source information in advisories, and sets called to false
func fillNotImportedAnalysisInfo(vulnsByID map[string]models.Vulnerability, vulnID string, pv models.PackageVulns, analysis *map[string]models.AnalysisInfo) {
	for _, v := range vulnsByID[vulnID].Affected {
		// TODO: Compare versions to see if this is the correct affected element
		// ver, err := semantic.Parse(pv.Package.Version, semantic.SemverVersion)
		if v.Package.Name != pv.Package.Name {
			continue
		}
		_, hasImportsField := v.EcosystemSpecific["imports"]
		if hasImportsField {
			// If there is source information, then analysis has been performed, and
			// code does not import the vulnerable package, so definitely not called
			(*analysis)[vulnID] = models.AnalysisInfo{
				Called: false,
			}
		}
	}
}
