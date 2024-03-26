package output

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/fatih/color"
	"github.com/google/osv-scanner/pkg/models"
)

func PrintVerticalResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	for _, result := range vulnResult.Results {
		fmt.Fprintln(outputWriter, toString(result))
	}
}

func countVulnerabilities(result models.PackageSource) int {
	count := 0

	for _, pkg := range result.Packages {
		count += len(pkg.Vulnerabilities)
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

func formatLineByLine(result models.PackageSource) string {
	lines := make([]string, 0, len(result.Packages))

	for _, pkg := range result.Packages {
		if len(pkg.Vulnerabilities) == 0 {
			continue
		}

		lines = append(lines, fmt.Sprintf(
			"  %s %s",
			color.YellowString("%s@%s", pkg.Package.Name, pkg.Package.Version),
			color.RedString("is affected by the following vulnerabilities:"),
		))

		for _, vulnerability := range pkg.Vulnerabilities {
			lines = append(lines, fmt.Sprintf(
				"    %s %s",
				color.CyanString("%s:", vulnerability.ID),
				describe(vulnerability),
			))
		}
	}

	return strings.Join(lines, "\n")
}

func toString(result models.PackageSource) string {
	count := countVulnerabilities(result)
	word := "known"

	out := ""
	out += fmt.Sprintf(
		"%s: found %s %s\n",
		color.MagentaString("%s", result.Source.Path),
		color.YellowString("%d", len(result.Packages)),
		Form(len(result.Packages), "package", "packages"),
	)

	if count == 0 {
		return out + fmt.Sprintf(
			"  %s\n",
			color.GreenString("no %s vulnerabilities found", word),
		)
	}

	out += "\n"
	out += formatLineByLine(result)
	out += "\n"

	out += fmt.Sprintf("\n  %s\n",
		color.RedString(
			"%d %s %s found in %s",
			count,
			word,
			Form(count, "vulnerability", "vulnerabilities"),
			result.Source.Path,
		),
	)

	return out
}
