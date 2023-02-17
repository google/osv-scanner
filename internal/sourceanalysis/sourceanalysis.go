package sourceanalysis

import (
	"fmt"
	"path/filepath"

	"github.com/google/osv-scanner/internal/govulncheckshim"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
)

// vulnsFromAllPkgs returns a map of IDs to GroupInfo pointers, and the extracted list of vulnerabilities
func vulnsFromAllPkgs(pkgs []models.PackageVulns) (map[string]*models.GroupInfo, []models.Vulnerability) {
	idToGroupMap := map[string]*models.GroupInfo{}
	vulnList := []models.Vulnerability{}
	for _, pv := range pkgs {
		for _, vuln := range pv.Vulnerabilities {
			groupIdx := slices.IndexFunc(pv.Groups, func(g models.GroupInfo) bool {
				return slices.Contains(g.IDs, vuln.ID)
			})

			idToGroupMap[vuln.ID] = &pv.Groups[groupIdx]
			vulnList = append(vulnList, vuln)
		}
	}

	return idToGroupMap, vulnList
}

// DoSourceAnalysis runs the language specific analyzers on the code given packages and source info
func DoSourceAnalysis(r *output.Reporter, source models.SourceInfo, pkgs []models.PackageVulns) {
	idToGroupMap, allVulns := vulnsFromAllPkgs(pkgs)

	// GoVulnCheck
	if source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" {
		res, err := govulncheckshim.RunGoVulnCheck(filepath.Dir(source.Path), allVulns)
		if err != nil {
			// TODO: Better method to identify the type of error and give advice specific to the error
			r.PrintError(
				fmt.Sprintf("Failed to run code analysis (govulncheck) on '%s' because %s\n"+
					"(the Go toolchain is required)\n", source.Path, err.Error()))

			return
		}
		// Add analysis information back into package list
		for _, v := range res.Vulns {
			analysis := &idToGroupMap[v.OSV.ID].ExperimentalAnalysis
			if *analysis == nil {
				*analysis = make(map[string]models.AnalysisInfo)
			}
			(*analysis)[v.OSV.ID] = models.AnalysisInfo{
				Called: v.IsCalled(),
			}
		}
	}
}
