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
		printVerticalVulnerabilities(result, outputWriter, true)

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

func collectVulns(pkg models.PackageVulns, called bool) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)

	for _, group := range pkg.Groups {
		if group.IsCalled() != called {
			continue
		}

		for _, ids := range group.IDs {
			for _, v := range pkg.Vulnerabilities {
				if v.ID == ids {
					vulns = append(vulns, v)
				}
			}
		}
	}

	return vulns
}

func printVerticalVulnerabilities(result models.PackageSource, out io.Writer, called bool) {
	count := countVulnerabilities(result)

	if count == 0 {
		fmt.Fprintf(
			out,
			"  %s\n",
			text.FgGreen.Sprintf("no known vulnerabilities found"),
		)

		return
	}

	fmt.Fprintln(out)

	for _, pkg := range result.Packages {
		vulns := collectVulns(pkg, called)

		if len(vulns) == 0 {
			continue
		}

		fmt.Fprintf(out,
			"  %s %s\n",
			text.FgYellow.Sprintf("%s@%s", pkg.Package.Name, pkg.Package.Version),
			text.FgRed.Sprintf("is affected by the following vulnerabilities:"),
		)

		for _, vulnerability := range vulns {
			fmt.Fprintf(out,
				"    %s %s\n",
				text.FgCyan.Sprintf("%s:", vulnerability.ID),
				describe(vulnerability),
			)
		}
	}

	fmt.Fprintf(out, "\n  %s\n",
		text.FgRed.Sprintf(
			"%d known %s found in %s",
			count,
			Form(count, "vulnerability", "vulnerabilities"),
			result.Source.Path,
		),
	)
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
			text.FgCyan.Sprintf(strings.Join(violations, ", ")),
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

func countVulnerabilities(result models.PackageSource) int {
	count := 0

	for _, pkg := range result.Packages {
		for _, g := range pkg.Groups {
			if g.IsCalled() {
				count += len(g.IDs)
			}
		}
	}

	return count
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
