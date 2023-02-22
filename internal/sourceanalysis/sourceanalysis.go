package sourceanalysis

import (
	"fmt"
	"path/filepath"

	"golang.org/x/exp/slices"

	"github.com/google/osv-scanner/internal/govulncheckshim"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

type MatchedVulnerability struct {
	vuln  models.Vulnerability
	group *models.GroupInfo
	pkg   models.PackageInfo
}

// vulnsFromAllPkgs returns a map of IDs to GroupInfo pointers, and the extracted list of vulnerabilities
func vulnsFromAllPkgs(pkgs []models.PackageVulns) (map[string]map[string]MatchedVulnerability, []models.Vulnerability) {
	idMatchedVulnMap := map[string]map[string]MatchedVulnerability{}
	flatVulns := map[string]models.Vulnerability{}
	for _, pv := range pkgs {
		for _, vuln := range pv.Vulnerabilities {
			groupIdx := slices.IndexFunc(pv.Groups, func(g models.GroupInfo) bool {
				return slices.Contains(g.IDs, vuln.ID)
			})

			if idMatchedVulnMap[pv.Package.Name] == nil {
				idMatchedVulnMap[pv.Package.Name] = make(map[string]MatchedVulnerability)
			}

			idMatchedVulnMap[pv.Package.Name][vuln.ID] = MatchedVulnerability{
				group: &pv.Groups[groupIdx],
				vuln:  vuln,
				pkg:   pv.Package,
			}

			flatVulns[vuln.ID] = vuln
		}
	}

	vulnList := []models.Vulnerability{}
	for _, v := range flatVulns {
		vulnList = append(vulnList, v)
	}

	return idMatchedVulnMap, vulnList
}

// Run runs the language specific analyzers on the code given packages and source info
func Run(r *output.Reporter, source models.SourceInfo, pkgs []models.PackageVulns) {
	idMatchedVulnMap, vulnsSlice := vulnsFromAllPkgs(pkgs)

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
		// Add analysis information back into package list
		for _, v := range res.Vulns {
			for _, m := range v.Modules {
				if idMatchedVulnMap[m.Path] == nil {
					continue
				}
				analysis := &idMatchedVulnMap[m.Path][v.OSV.ID].group.ExperimentalAnalysis
				if *analysis == nil {
					*analysis = make(map[string]models.AnalysisInfo)
				}
				(*analysis)[v.OSV.ID] = models.AnalysisInfo{
					Called: v.IsCalled(),
				}
			}

		}
	}
}
