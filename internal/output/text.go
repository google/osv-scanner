package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/internal/osv"
	"github.com/google/osv-scanner/pkg/models"
)

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
			summaries := make(map[string]string)
			for _, vuln := range pkg.Vulnerabilities {
				summaries[vuln.ID] = vuln.Summary
			}

			var groupDigits int
			switch {
			case len(pkg.Groups) < 10:
				groupDigits = 1
			case len(pkg.Groups) < 100:
				groupDigits = 2
			default:
				// There are bigger problems than formatting if a package has more than 999 vulnerabilities
				groupDigits = 3
			}

			for i, group := range pkg.Groups {
				var noSummary []string
				var withSummary []string
				pad := 0
				for _, vuln := range group.IDs {
					if len(vuln) > pad {
						pad = len(vuln)
					}
					if len(summaries[vuln]) > 0 {
						withSummary = append(withSummary, vuln)
					} else {
						noSummary = append(noSummary, vuln)
					}
				}

				pad += len(osv.BaseVulnerabilityURL)
				vulnStrings := make([]string, 0, len(group.IDs))
				for _, vuln := range noSummary {
					vulnStrings = append(vulnStrings, fmt.Sprintf("%s", osv.BaseVulnerabilityURL+vuln))
				}
				for _, vuln := range withSummary {
					vulnStrings = append(vulnStrings, fmt.Sprintf("%-*s - %s", pad, osv.BaseVulnerabilityURL+vuln, summaries[vuln]))
				}

				fmt.Fprintf(outputWriter, "    %*d. %s\n", groupDigits, i+1, vulnStrings[0])
				for _, vulnStr := range vulnStrings[1:] {
					fmt.Fprintf(outputWriter, "    %*c  %s\n", groupDigits, ' ', vulnStr)
				}

			}
		}

	}
}
