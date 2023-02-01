package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/osv-scanner/internal/osv"
	"github.com/google/osv-scanner/pkg/models"
)

// get a description for the vulnerability, truncated to maxLen long.
// If maxLen < 0, do not truncate.
func vulnDescription(vuln models.Vulnerability, maxLen int) string {
	if maxLen > 0 && maxLen < 3 {
		maxLen = 3
	}
	description := vuln.Summary
	if len(description) == 0 {
		description = vuln.Details
	}
	if len(description) == 0 {
		if maxLen > 0 && maxLen < len("(no details available)") {
			return "..."
		}
		return "(no details available)"
	}

	// Only use the first line of a multi-line description.
	description, _, _ = strings.Cut(description, "\n")
	if maxLen < 0 || len([]rune(description)) <= maxLen {
		return description
	}

	// Find a nice place to truncate the string if too long, ideally not wihtin a word.
	runes := []rune(description)[:maxLen-3]
	for i := maxLen - 4; i >= 0; i-- {
		if unicode.IsSpace(runes[i]) {
			return string(runes[:i]) + "..."
		}
	}
	return string(runes) + "..."
}

// PrintTextResults prints the osv scan results as text.
func PrintTextResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	for _, sourceRes := range vulnResult.Results {
		workingDir, err := os.Getwd()
		source := sourceRes.Source
		if err == nil {
			sourcePath, err := filepath.Rel(workingDir, source.Path)
			if err == nil { // Simplify the path if possible
				source.Path = sourcePath
			}
		}
		fmt.Fprintf(outputWriter, "\n%s:\n", source.Path)

		for _, pkg := range sourceRes.Packages {
			fmt.Fprintf(outputWriter, "  %s@%s is affected by the following vulnerabilities:\n", pkg.Package.Name, pkg.Package.Version)
			descriptions := make(map[string]string)
			for _, vuln := range pkg.Vulnerabilities {
				descriptions[vuln.ID] = vulnDescription(vuln, 80)
			}

			for i, group := range pkg.Groups {
				pad := 0
				for _, vuln := range group.IDs {
					if len(vuln) > pad {
						pad = len(vuln)
					}
				}

				pad += len(osv.BaseVulnerabilityURL)
				vulnStrings := make([]string, 0, len(group.IDs))
				for _, vuln := range group.IDs {
					vulnStrings = append(vulnStrings, fmt.Sprintf("%-*s - %s", pad, osv.BaseVulnerabilityURL+vuln, descriptions[vuln]))
				}

				fmt.Fprintf(outputWriter, "    %3d. %s\n", i+1, vulnStrings[0])
				for _, vulnStr := range vulnStrings[1:] {
					fmt.Fprintf(outputWriter, "         %s\n", vulnStr)
				}
			}
		}
	}
}
