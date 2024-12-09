package fix

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

type fixResult struct {
	Path            string           `json:"path"`
	Ecosystem       models.Ecosystem `json:"ecosystem"`
	Strategy        strategy         `json:"strategy"`
	Vulnerabilities []fixVuln        `json:"vulnerabilities"`
	Patches         []fixPatch       `json:"patches"`
	Errors          []fixError       `json:"errors,omitempty"`
}

type fixVuln struct {
	ID           string               `json:"id"`
	Packages     []fixAffectedPackage `json:"packages"`
	Unactionable bool                 `json:"unactionable,omitempty"`
}

type fixPatch struct {
	PackageUpdates []fixPackageUpdate `json:"packageUpdates"`
	Fixed          []fixVuln          `json:"fixed"`
	Introduced     []fixVuln          `json:"introduced,omitempty"`
}

type fixAffectedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type fixPackageUpdate struct {
	Name        string `json:"name"`
	VersionFrom string `json:"versionFrom"`
	VersionTo   string `json:"versionTo"`
	Transitive  bool   `json:"transitive"`
}

type fixError struct {
	Package     fixAffectedPackage `json:"package"`
	Requirement fixAffectedPackage `json:"requirement"`
	Error       string             `json:"error"`
}

func outputText(w io.Writer, res fixResult) {
	if len(res.Errors) > 0 {
		fmt.Fprintf(w, "WARNING: encountered %d errors during dependency resolution:\n", len(res.Errors))
		for _, err := range res.Errors {
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

	nVulns := len(res.Vulnerabilities)

	fmt.Fprintf(w, "Found %d vulnerabilities matching the filter\n", nVulns)

	if len(res.Patches) == 0 {
		fmt.Fprintf(w, "No dependency patches are possible\n")
		fmt.Fprintf(w, "REMAINING-VULNS: %d\n", nVulns)
		fmt.Fprintf(w, "UNFIXABLE-VULNS: %d\n", nVulns)

		return
	}

	changedDeps := 0
	var fixedVulns []string
	for _, patch := range res.Patches {
		changedDeps += len(patch.PackageUpdates)
		for _, v := range patch.Fixed {
			fixedVulns = append(fixedVulns, v.ID)
		}
	}

	if res.Strategy == strategyOverride {
		fmt.Fprintf(w, "Can fix %d/%d matching vulnerabilities by overriding %d dependencies\n", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range res.Patches {
			for _, pkg := range patch.PackageUpdates {
				fmt.Fprintf(w, "OVERRIDE-PACKAGE: %s,%s\n", pkg.Name, pkg.VersionTo)
			}
		}
	} else {
		fmt.Fprintf(w, "Can fix %d/%d matching vulnerabilities by changing %d dependencies\n", len(fixedVulns), nVulns, changedDeps)
		for _, patch := range res.Patches {
			for _, pkg := range patch.PackageUpdates {
				fmt.Fprintf(w, "UPGRADED-PACKAGE: %s,%s,%s\n", pkg.Name, pkg.VersionFrom, pkg.VersionTo)
			}
		}
	}
	slices.Sort(fixedVulns)
	fmt.Fprintf(w, "FIXED-VULN-IDS: %s\n", strings.Join(fixedVulns, ","))
	fmt.Fprintf(w, "REMAINING-VULNS: %d\n", nVulns-len(fixedVulns))

	nUnfixable := 0
	for _, v := range res.Vulnerabilities {
		if v.Unactionable {
			nUnfixable++
		}
	}
	fmt.Fprintf(w, "UNFIXABLE-VULNS: %d\n", nUnfixable)
}
