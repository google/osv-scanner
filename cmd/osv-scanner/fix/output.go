package fix

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

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
