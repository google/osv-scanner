package output

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

func PrintVerticalResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	for i, result := range vulnResult.Results {
		printVerticalHeader(result, outputWriter)
		printVerticalVulnerabilities(result, outputWriter)

		if len(vulnResult.ExperimentalAnalysisConfig.Licenses.Allowlist) > 0 {
			printVerticalLicenseViolations(result, outputWriter)
		}

		if i < len(vulnResult.Results)-1 {
			fmt.Fprintln(outputWriter)
		}
	}
}

func printVerticalHeader(result models.PackageSource, out io.Writer) {
	fmt.Fprintf(
		out,
		"%s: found %s %s with issues\n",
		text.FgMagenta.Sprintf("%s", result.Source.Path),
		text.FgYellow.Sprintf("%d", len(result.Packages)),
		Form(len(result.Packages), "package", "packages"),
	)
}

func printVerticalVulnerabilitiesCountSummary(count int, state string, sourcePath string, out io.Writer) {
	fmt.Fprintf(out, "\n  %s\n",
		text.FgRed.Sprintf(
			"%d %s %s found in %s",
			count,
			state,
			Form(count, "vulnerability", "vulnerabilities"),
			sourcePath,
		),
	)
}

func collectVulns(pkg models.PackageVulns, called bool) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)

	for _, group := range pkg.Groups {
		if group.IsCalled() != called {
			continue
		}

		for _, id := range group.IDs {
			for _, v := range pkg.Vulnerabilities {
				if v.ID == id {
					vulns = append(vulns, v)
				}
			}
		}
	}

	return vulns
}

func printVerticalVulnerabilitiesForPackages(result models.PackageSource, out io.Writer, printingCalled bool) {
	for _, pkg := range result.Packages {
		vulns := collectVulns(pkg, printingCalled)

		if len(vulns) == 0 {
			continue
		}

		state := "uncalled"
		if printingCalled {
			state = "known"
		}

		fmt.Fprintf(out,
			"  %s %s\n",
			text.FgYellow.Sprintf("%s@%s", pkg.Package.Name, pkg.Package.Version),
			text.FgRed.Sprintf("has the following %s vulnerabilities:", state),
		)

		for _, vulnerability := range vulns {
			fmt.Fprintf(out,
				"    %s %s\n",
				text.FgCyan.Sprintf("%s:", vulnerability.ID),
				describe(vulnerability),
			)
		}
	}
}

func printVerticalVulnerabilities(result models.PackageSource, out io.Writer) {
	countCalled, countUncalled := countVulnerabilities(result)

	if countCalled == 0 && countUncalled == 0 {
		fmt.Fprintf(
			out,
			"  %s\n",
			text.FgGreen.Sprintf("no known vulnerabilities found"),
		)

		return
	}

	if countCalled > 0 {
		fmt.Fprintln(out)

		printVerticalVulnerabilitiesForPackages(result, out, true)
		printVerticalVulnerabilitiesCountSummary(countCalled, "known", result.Source.Path, out)
	}

	if countUncalled > 0 {
		fmt.Fprintln(out)

		printVerticalVulnerabilitiesForPackages(result, out, false)
		printVerticalVulnerabilitiesCountSummary(countUncalled, "uncalled", result.Source.Path, out)
	}
}

func printVerticalLicenseViolations(result models.PackageSource, out io.Writer) {
	count := countLicenseViolations(result)

	if count == 0 {
		fmt.Fprintf(
			out,
			"  %s\n",
			text.FgGreen.Sprintf("no license violations found"),
		)

		return
	}

	fmt.Fprintf(out, "\n  %s\n", text.FgRed.Sprintf("license violations found:"))

	for _, pkg := range result.Packages {
		if len(pkg.LicenseViolations) == 0 {
			continue
		}

		violations := make([]string, len(pkg.LicenseViolations))
		for i, l := range pkg.LicenseViolations {
			violations[i] = string(l)
		}

		fmt.Fprintf(out,
			"    %s (%s)\n",
			text.FgYellow.Sprintf("%s@%s", pkg.Package.Name, pkg.Package.Version),
			text.FgCyan.Sprintf("%s", strings.Join(violations, ", ")),
		)
	}

	fmt.Fprintf(out, "\n  %s\n",
		text.FgRed.Sprintf(
			"%d license %s found in %s",
			count,
			Form(count, "violation", "violations"),
			result.Source.Path,
		),
	)
}

func countVulnerabilities(result models.PackageSource) (called int, uncalled int) {
	for _, pkg := range result.Packages {
		for _, group := range pkg.Groups {
			for _, id := range group.IDs {
				for _, v := range pkg.Vulnerabilities {
					if v.ID == id {
						if group.IsCalled() {
							called++
						} else {
							uncalled++
						}
					}
				}
			}
		}
	}

	return
}

func countLicenseViolations(result models.PackageSource) int {
	count := 0

	for _, pkg := range result.Packages {
		count += len(pkg.LicenseViolations)
	}

	return count
}

// truncate ensures that the given string is shorter than the provided limit.
//
// If the string is longer than the limit, it's trimmed and suffixed with an ellipsis.
// Ideally the string will be trimmed at the space that's closest to the limit to
// preserve whole words; if a string has no spaces before the limit, it'll be forcefully truncated.
func truncate(str string, limit int) string {
	count := 0
	truncateAt := -1

	for i, c := range str {
		if unicode.IsSpace(c) {
			truncateAt = i
		}

		count++

		if count >= limit {
			// ideally we want to keep words whole when truncating,
			// but if we can't find a space just truncate at the limit
			if truncateAt == -1 {
				truncateAt = limit
			}

			return str[:truncateAt] + "..."
		}
	}

	return str
}

func describe(vulnerability models.Vulnerability) string {
	description := vulnerability.Summary

	if description == "" {
		description += truncate(vulnerability.Details, 80)
	}

	if description == "" {
		description += "(no details available)"
	}

	description += " (" + OSVBaseVulnerabilityURL + vulnerability.ID + ")"

	return description
}
