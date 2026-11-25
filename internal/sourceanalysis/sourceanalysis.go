package sourceanalysis

import (
	"context"
	"os/exec"
	"path/filepath"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Options carries the explicit execution state for source analysis.
//
// Language analyzers receive this value rather than inspecting globals or the
// ambient environment, so the offline decision has a single, auditable source:
// ScannerActions.PluginNetworkDisabled.
type Options struct {
	// Offline is true for --offline. It is deliberately independent of
	// CompareOffline (--offline-vulnerabilities): the latter only switches the
	// vulnerability database and does not disable network access for call
	// analysis.
	Offline bool
}

// commandFactory is the seam used by tests to observe subprocess creation.
// Production code always uses exec.CommandContext.
type commandFactory func(ctx context.Context, name string, args ...string) *exec.Cmd

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
func Run(source models.SourceInfo, pkgs []models.PackageVulns, callAnalysis map[string]bool, opts Options) {
	run(source, pkgs, callAnalysis, opts, exec.CommandContext)
}

func run(
	source models.SourceInfo,
	pkgs []models.PackageVulns,
	callAnalysis map[string]bool,
	opts Options,
	newCommand commandFactory,
) {
	if newCommand == nil {
		newCommand = exec.CommandContext
	}

	// GoVulnCheck
	if source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" && callAnalysis["go"] {
		goAnalysis(pkgs, source, opts.Offline)
	}

	if source.Type == "lockfile" && filepath.Base(source.Path) == "Cargo.lock" && callAnalysis["rust"] {
		rustAnalysis(pkgs, source, opts.Offline, newCommand)
	}
}
