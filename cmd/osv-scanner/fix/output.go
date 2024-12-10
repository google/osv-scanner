package fix

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

type fixOutput struct {
	Path            string           `json:"path"`
	Ecosystem       models.Ecosystem `json:"ecosystem"`
	Strategy        strategy         `json:"strategy"`
	Vulnerabilities []vulnOutput     `json:"vulnerabilities"`
	Patches         []patchOutput    `json:"patches"`
	Errors          []errorOutput    `json:"errors,omitempty"`
}

type vulnOutput struct {
	ID           string          `json:"id"`
	Packages     []packageOutput `json:"packages"`
	Unactionable bool            `json:"unactionable,omitempty"`
}

type patchOutput struct {
	PackageUpdates []updatePackageOutput `json:"packageUpdates"`
	Fixed          []vulnOutput          `json:"fixed"`
	Introduced     []vulnOutput          `json:"introduced,omitempty"`
}

type packageOutput struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type updatePackageOutput struct {
	Name        string `json:"name"`
	VersionFrom string `json:"versionFrom"`
	VersionTo   string `json:"versionTo"`
	Transitive  bool   `json:"transitive"`
}

type errorOutput struct {
	Package     packageOutput `json:"package"`
	Requirement packageOutput `json:"requirement"`
	Error       string        `json:"error"`
}

// TODO: stop relying on old reporter implementation
type outputReporter struct {
	Stdout       io.Writer
	Stderr       io.Writer
	OutputResult func(fixOutput) error
	hasErrored   bool
}

func (r *outputReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.Stderr, format, a...)
	r.hasErrored = true
}

func (r *outputReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *outputReporter) Warnf(format string, a ...any) {
	fmt.Fprintf(r.Stdout, format, a...)
}

func (r *outputReporter) Infof(format string, a ...any) {
	fmt.Fprintf(r.Stdout, format, a...)
}

func (r *outputReporter) Verbosef(format string, a ...any) {
	fmt.Fprintf(r.Stdout, format, a...)
}

func (r *outputReporter) PrintResult(*models.VulnerabilityResults) error {
	panic("not implemented")
}

func outputText(w io.Writer, out fixOutput) error {
	if len(out.Errors) > 0 {
		fmt.Fprintf(w, "WARNING: encountered %d errors during dependency resolution:\n", len(out.Errors))
		for _, err := range out.Errors {
			fmt.Fprintf(w, "Error when resolving %s@%s:\n", err.Package.Name, err.Package.Version)
			if strings.Contains(err.Requirement.Version, ":") {
				// this will be the case with unsupported npm requirements e.g. `file:...`, `git+https://...`
				// TODO: don't rely on resolution to propagate these errors
				// No easy access to the `knownAs` field to find which package this corresponds to
				fmt.Fprintf(w, "\tSkipped resolving unsupported version specification: %s\n", err.Requirement.Version)
			} else {
				fmt.Fprintf(w, "\t%v: %s@%s\n", err.Error, err.Requirement.Name, err.Requirement.Version)
			}
		}
	}

	nVulns := len(out.Vulnerabilities)

	fmt.Fprintf(w, "Found %d vulnerabilities matching the filter\n", nVulns)

	if len(out.Patches) == 0 {
		fmt.Fprintf(w, "No dependency patches are possible\n")
		fmt.Fprintf(w, "REMAINING-VULNS: %d\n", nVulns)
		fmt.Fprintf(w, "UNFIXABLE-VULNS: %d\n", nVulns)

		return nil
	}

	changedDeps := 0
	var fixedVulns []string
	for _, patch := range out.Patches {
		changedDeps += len(patch.PackageUpdates)
		for _, v := range patch.Fixed {
			fixedVulns = append(fixedVulns, v.ID)
		}
	}

	if out.Strategy == strategyOverride {
		fmt.Fprintf(w, "Can fix %d/%d matching vulnerabilities by overriding %d dependencies\n", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range out.Patches {
			for _, pkg := range patch.PackageUpdates {
				fmt.Fprintf(w, "OVERRIDE-PACKAGE: %s,%s\n", pkg.Name, pkg.VersionTo)
			}
		}
	} else {
		fmt.Fprintf(w, "Can fix %d/%d matching vulnerabilities by changing %d dependencies\n", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range out.Patches {
			for _, pkg := range patch.PackageUpdates {
				fmt.Fprintf(w, "UPGRADED-PACKAGE: %s,%s,%s\n", pkg.Name, pkg.VersionFrom, pkg.VersionTo)
			}
		}
	}
	slices.Sort(fixedVulns)
	fmt.Fprintf(w, "FIXED-VULN-IDS: %s\n", strings.Join(fixedVulns, ","))
	fmt.Fprintf(w, "REMAINING-VULNS: %d\n", nVulns-len(fixedVulns))

	nUnfixable := 0
	for _, v := range out.Vulnerabilities {
		if v.Unactionable {
			nUnfixable++
		}
	}
	fmt.Fprintf(w, "UNFIXABLE-VULNS: %d\n", nUnfixable)

	return nil
}

func outputJSON(w io.Writer, out fixOutput) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(out)
}
