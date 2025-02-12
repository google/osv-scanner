package sourceanalysis

import (
	"path/filepath"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// vulnsFromAllPkgs returns the flattened list of unique vulnerabilities
func vulnsFromAllPkgs(pkgs []models.PackageVulns) ([]osvschema.Vulnerability, map[string]osvschema.Vulnerability) {
	flatVulns := map[string]osvschema.Vulnerability{}
	for _, pv := range pkgs {
		for _, vuln := range pv.Vulnerabilities {
			flatVulns[vuln.ID] = vuln
		}
	}

	vulns := []osvschema.Vulnerability{}
	for _, v := range flatVulns {
		vulns = append(vulns, v)
	}

	return vulns, flatVulns
}

// Run runs the language specific analyzers on the code given packages and source info
func Run(source models.SourceInfo, pkgs []models.PackageVulns, callAnalysis map[string]bool) {
	// GoVulnCheck
	if source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" && callAnalysis["go"] {
		goAnalysis(pkgs, source)
	}

	if source.Type == "lockfile" && filepath.Base(source.Path) == "Cargo.lock" && callAnalysis["rust"] {
		rustAnalysis(pkgs, source)
	}
}
