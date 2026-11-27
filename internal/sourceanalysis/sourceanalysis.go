package sourceanalysis

import (
	"path/filepath"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// vulnsFromAllPkgs returns the flattened list of unique vulnerabilities
func vulnsFromAllPkgs(pkgs []models.PackageVulns) ([]*osvschema.Vulnerability, map[string]*osvschema.Vulnerability) {
	flatVulns := map[string]*osvschema.Vulnerability{}
	for _, pv := range pkgs {
		for _, vuln := range pv.Vulnerabilities {
			flatVulns[vuln.GetId()] = vuln
		}
	}

	vulns := make([]*osvschema.Vulnerability, 0, len(flatVulns))
	for _, v := range flatVulns {
		vulns = append(vulns, v)
	}

	return vulns, flatVulns
}

// Run runs the language specific analyzers on the code given packages and source info
//
// Analysis is skipped when offline, as the analyzers rely on external toolchains
// (e.g. go, cargo) that can make network requests to fetch missing dependencies.
func Run(source models.SourceInfo, pkgs []models.PackageVulns, callAnalysis map[string]bool, offline bool) {
	isGo := source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" && callAnalysis["go"]
	isRust := source.Type == "lockfile" && filepath.Base(source.Path) == "Cargo.lock" && callAnalysis["rust"]

	if offline {
		if isGo || isRust {
			cmdlogger.Infof("Skipping call analysis on '%s' as it is disabled in offline mode", source.Path)
		}

		return
	}

	// GoVulnCheck
	if isGo {
		goAnalysis(pkgs, source)
	}

	if isRust {
		rustAnalysis(pkgs, source)
	}
}
