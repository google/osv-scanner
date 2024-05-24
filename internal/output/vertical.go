package output

import (
	"fmt"
	"io"
	"unicode"

	"github.com/fatih/color"
	"github.com/google/osv-scanner/pkg/models"
)

func PrintVerticalResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	for _, result := range vulnResult.Results {
		printVerticalHeader(result, outputWriter)
		printVerticalVulnerabilities(result, outputWriter)

		if len(vulnResult.ExperimentalAnalysisConfig.Licenses.Allowlist) > 0 {
			printVerticalLicenseViolations(result, outputWriter)
		}
	}
}

func printVerticalHeader(result models.PackageSource, out io.Writer) {
	fmt.Fprintf(
		out,
		"%s: found %s %s\n",
		color.MagentaString("%s", result.Source.Path),
		color.YellowString("%d", len(result.Packages)),
		Form(len(result.Packages), "package", "packages"),
	)
}

func printVerticalVulnerabilities(result models.PackageSource, out io.Writer) {
	count := countVulnerabilities(result)

	if count == 0 {
		fmt.Fprintf(
			out,
			"  %s\n",
			color.GreenString("no known vulnerabilities found"),
		)

		return
	}

	fmt.Fprintln(out)

	for _, pkg := range result.Packages {
		if len(pkg.Vulnerabilities) == 0 {
			continue
		}

		fmt.Fprintf(out,
			"  %s %s\n",
			color.YellowString("%s@%s", pkg.Package.Name, pkg.Package.Version),
			color.RedString("is affected by the following vulnerabilities:"),
		)

		for _, vulnerability := range pkg.Vulnerabilities {
			fmt.Fprintf(out,
				"    %s %s\n",
				color.CyanString("%s:", vulnerability.ID),
				describe(vulnerability),
			)
		}
	}

	fmt.Fprintf(out, "\n  %s\n",
		color.RedString(
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
			color.GreenString("no license violations found"),
		)

		return
	}

	for _, pkg := range result.Packages {
		if len(pkg.LicenseViolations) == 0 {
			continue
		}

		fmt.Fprintf(out,
			"  %s %s %s\n",
			color.YellowString("%s@%s", pkg.Package.Name, pkg.Package.Version),
			color.RedString("is using an incompatible license:"),
			// todo: handle multiple licenses
			color.CyanString(string(pkg.LicenseViolations[0])),
		)
	}

	fmt.Fprintf(out, "\n  %s\n",
		color.RedString(
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
		count += len(pkg.Vulnerabilities)
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
