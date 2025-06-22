package fix

import (
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// fixOutput is a description of changes made by guided remediation to a manifest/lockfile.
type fixOutput struct {
	Path            string              `json:"path"`             // path to the manifest/lockfile.
	Ecosystem       osvschema.Ecosystem `json:"ecosystem"`        // the OSV ecosystem of the file (npm, Maven)
	Strategy        strategy            `json:"strategy"`         // the remediation strategy that was used.
	Vulnerabilities []vulnOutput        `json:"vulnerabilities"`  // vulns detected in the initial manifest/lockfile.
	Patches         []patchOutput       `json:"patches"`          // list of dependency patches that were applied.
	Errors          []errorOutput       `json:"errors,omitempty"` // non-fatal errors encountered in initial resolution.
}

// vulnOutput represents a vulnerability that was found in a project.
type vulnOutput struct {
	ID           string          `json:"id"`                     // the OSV ID of the vulnerability.
	Packages     []packageOutput `json:"packages"`               // the list of packages in the dependency graph this vuln affects.
	Unactionable bool            `json:"unactionable,omitempty"` // true if no fix patch available, or if constraints would prevent one.
}

// patchOutput represents an isolated patch to one or more dependencies that fixes one or more vulns.
type patchOutput struct {
	PackageUpdates []updatePackageOutput `json:"packageUpdates"`       // dependencies that were updated.
	Fixed          []vulnOutput          `json:"fixed"`                // vulns fixed by this patch.
	Introduced     []vulnOutput          `json:"introduced,omitempty"` // vulns introduced by this patch.
}

// packageOutput represents a package that was found in a project.
type packageOutput struct {
	Name    string `json:"name"`    // name of the dependency.
	Version string `json:"version"` // version of the dependency in the graph.
}

// updatePackageOutput represents a package that was updated by a patch.
type updatePackageOutput struct {
	Name        string `json:"name"`        // name of dependency being updated.
	VersionFrom string `json:"versionFrom"` // version of the dependency before the patch.
	VersionTo   string `json:"versionTo"`   // version of the dependency after the patch.
	Transitive  bool   `json:"transitive"`  // false if this package is a direct dependency, true if indirect.
}

// errorOutput represents an error encountered during the initial resolution of the dependency graph.
type errorOutput struct {
	Package     packageOutput `json:"package"`     // the package that caused the error.
	Requirement packageOutput `json:"requirement"` // the requirement of the package that errored.
	Error       string        `json:"error"`       // the error string.
	// e.g.
	// errorOutput{
	// 	  Package:     affectedPackage{"foo", "1.2.3"},
	// 	  Requirement: affectedPackage{"bar", ">2.0.0"},
	//	  Error:       "could not find a version that satisfies requirement >2.0.0 for package bar",
	// }
}

func printResult(outputResult fixOutput, opts osvFixOptions) error {
	if opts.OutputJSON {
		return outputJSON(opts.Stdout, outputResult)
	}

	return outputText(opts.Stdout, outputResult)
}

func outputText(_ io.Writer, out fixOutput) error {
	if len(out.Errors) > 0 {
		cmdlogger.Warnf("WARNING: encountered %d errors during dependency resolution:", len(out.Errors))
		for _, err := range out.Errors {
			cmdlogger.Errorf("Error when resolving %s@%s:", err.Package.Name, err.Package.Version)
			if strings.Contains(err.Requirement.Version, ":") {
				// this will be the case with unsupported npm requirements e.g. `file:...`, `git+https://...`
				// TODO: don't rely on resolution to propagate these errors
				// No easy access to the `knownAs` field to find which package this corresponds to
				cmdlogger.Errorf("\tSkipped resolving unsupported version specification: %s", err.Requirement.Version)
			} else {
				cmdlogger.Errorf("\t%v: %s@%s", err.Error, err.Requirement.Name, err.Requirement.Version)
			}
		}
	}

	nVulns := len(out.Vulnerabilities)

	cmdlogger.Infof("Found %d vulnerabilities matching the filter", nVulns)

	if len(out.Patches) == 0 {
		cmdlogger.Infof("No dependency patches are possible")
		cmdlogger.Infof("REMAINING-VULNS: %d", nVulns)
		cmdlogger.Infof("UNFIXABLE-VULNS: %d", nVulns)

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
		cmdlogger.Infof("Can fix %d/%d matching vulnerabilities by overriding %d dependencies", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range out.Patches {
			for _, pkg := range patch.PackageUpdates {
				cmdlogger.Infof("OVERRIDE-PACKAGE: %s,%s", pkg.Name, pkg.VersionTo)
			}
		}
	} else {
		cmdlogger.Infof("Can fix %d/%d matching vulnerabilities by changing %d dependencies", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range out.Patches {
			for _, pkg := range patch.PackageUpdates {
				cmdlogger.Infof("UPGRADED-PACKAGE: %s,%s,%s", pkg.Name, pkg.VersionFrom, pkg.VersionTo)
			}
		}
	}
	slices.Sort(fixedVulns)
	cmdlogger.Infof("FIXED-VULN-IDS: %s", strings.Join(fixedVulns, ","))
	cmdlogger.Infof("REMAINING-VULNS: %d", nVulns-len(fixedVulns))

	nUnfixable := 0
	for _, v := range out.Vulnerabilities {
		if v.Unactionable {
			nUnfixable++
		}
	}
	cmdlogger.Infof("UNFIXABLE-VULNS: %d", nUnfixable)

	return nil
}

func outputJSON(w io.Writer, out fixOutput) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(out)
}
