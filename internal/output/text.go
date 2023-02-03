package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"

	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

// get a description for the vulnerability, truncated to maxLen long.
// If maxLen < 0, do not truncate.
func vulnDescription(vuln models.Vulnerability) string {
	description := vuln.Summary
	if len(description) == 0 {
		description = vuln.Details
	}
	if len(description) == 0 {

		return "(no details available)"
	}

	// Only use the first line of a multi-line description.
	description, _, _ = strings.Cut(description, "\n")

	return description
}

// PrintTextResults prints the osv scan results as text.
func PrintTextResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	const maxWidth = 120
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	isTerminal := false
	if err == nil {
		isTerminal = true
		if width > maxWidth {
			width = maxWidth
		}
	} else {
		width = maxWidth
	}
	for _, sourceRes := range vulnResult.Results {
		workingDir, err := os.Getwd()
		source := sourceRes.Source
		if err == nil {
			sourcePath, err := filepath.Rel(workingDir, source.Path)
			if err == nil { // Simplify the path if possible
				source.Path = sourcePath
			}
		}
		if isTerminal {
			fmt.Fprintf(outputWriter, "\n%s:\n", text.FgMagenta.Sprint(source.Path))
		} else {
			fmt.Fprintf(outputWriter, "\n%s:\n", source.Path)
		}

		for _, pkg := range sourceRes.Packages {
			if isTerminal {
				pkgver := text.Color.Sprintf(text.FgYellow, "%s@%s", pkg.Package.Name, pkg.Package.Version)
				line := text.Color.Sprintf(text.FgRed, "  %s is affected by the following vulnerabilities:", pkgver)
				fmt.Fprintln(outputWriter, line)
			} else {
				fmt.Fprintf(outputWriter, "  %s@%s is affected by the following vulnerabilities:\n", pkg.Package.Name, pkg.Package.Version)
			}

			descriptions := make(map[string]string)
			maxLen := 0
			for _, vuln := range pkg.Vulnerabilities {
				descriptions[vuln.ID] = vulnDescription(vuln)
				if len(vuln.ID) > maxLen {
					maxLen = len(vuln.ID)
				}
			}
			maxLen += len(osv.BaseVulnerabilityURL)

			for i, group := range pkg.Groups {
				vulnStrings := make([]string, 0, len(group.IDs))
				for _, vuln := range group.IDs {
					var vulnID string
					if isTerminal {
						vulnID = text.Color.Sprint(text.FgCyan, osv.BaseVulnerabilityURL+text.Bold.Sprint(vuln))
					} else {
						vulnID = osv.BaseVulnerabilityURL + vuln
					}
					vulnID = text.AlignLeft.Apply(vulnID, maxLen)
					vulnStrings = append(vulnStrings, fmt.Sprintf("%s - %s", vulnID, descriptions[vuln]))
				}

				line := fmt.Sprintf("    %3d. %s", i+1, vulnStrings[0])
				fmt.Fprintln(outputWriter, text.Snip(line, width, "..."))
				for _, vulnStr := range vulnStrings[1:] {
					line := fmt.Sprintf("         %s", vulnStr)
					fmt.Fprintln(outputWriter, text.Snip(line, width, "..."))
				}
			}
		}
	}
}
