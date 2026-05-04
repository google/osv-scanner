package output

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
)

// createSourceRemediationTable creates a vulnerability table which includes the fixed versions for a specific source file
func createSourceRemediationTable(source models.PackageSource, groupedFixedVersions map[string][]string) (table.Writer, bool) {
	hasRow := false
	remediationTable := table.NewWriter()
	remediationTable.AppendHeader(table.Row{"Package", "Vulnerability ID", "CVSS", "Current Version", "Fixed Version"})

	for _, pv := range source.Packages {
		for _, group := range pv.Groups {
			fixedVersions := groupedFixedVersions[source.Source.String()+":"+group.IndexString()]

			vulnIDs := make([]string, 0, len(group.IDs))
			for _, id := range group.IDs {
				vulnIDs = append(vulnIDs, "https://osv.dev/"+id)
			}
			remediationTable.AppendRow(table.Row{
				pv.Package.Name,
				strings.Join(vulnIDs, "\n"),
				group.MaxSeverity,
				pv.Package.Version,
				strings.Join(fixedVersions, "\n")})
			hasRow = true
		}
	}

	return remediationTable, hasRow
}

func createDeprecationTable(source models.PackageSource) (table.Writer, bool) {
	hasRow := false
	deprecationTable := table.NewWriter()
	deprecationTable.AppendHeader(table.Row{"Package", "Current Version", "Deprecated"})

	for _, pv := range source.Packages {
		if pv.Package.Deprecated {
			deprecationTable.AppendRow(table.Row{
				pv.Package.Name,
				pv.Package.Version,
				pv.Package.Deprecated,
			})
			hasRow = true
		}
	}

	return deprecationTable, hasRow
}

// PrintGHAnnotationReport prints GitHub specific annotations to outputWriter
func PrintGHAnnotationReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	flattened := vulnResult.Flatten()

	// TODO: Also support last affected
	groupedFixedVersions := groupFixedVersions(flattened)
	workingDir := mustGetWorkingDirectory()

	for _, source := range vulnResult.Results {
		if len(source.Packages) == 0 {
			continue
		}
		// TODO: Support docker images

		var artifactPath string
		var err error
		artifactPath, err = filepath.Rel(workingDir, source.Source.Path)
		if err != nil {
			artifactPath = source.Source.Path
		}

		artifactPath = filepath.ToSlash(artifactPath)

		// Sanitize artifactPath to prevent GitHub Actions workflow command injection.
		// \r and \n in the file= parameter can terminate the annotation early and inject
		// arbitrary workflow commands (e.g. ::warning::, ::add-mask::) into the runner output.
		artifactPath = strings.ReplaceAll(artifactPath, "\r", "%0D")
		artifactPath = strings.ReplaceAll(artifactPath, "\n", "%0A")

		remediationTable, hasVulnTable := createSourceRemediationTable(source, groupedFixedVersions)
		if hasVulnTable {
			renderedTable := remediationTable.Render()
			// This is required as github action annotations must be on the same terminal line
			// so we URL encode the new line character
			renderedTable = strings.ReplaceAll(renderedTable, "\n", "%0A")
			// Sanitize \r to prevent workflow command injection via carriage return in package names
			renderedTable = strings.ReplaceAll(renderedTable, "\r", "%0D")

			// Prepend the table with a new line to look nicer in the output
			fmt.Fprintf(outputWriter, "::error file=%s::%s%s", artifactPath, artifactPath, "%0A"+renderedTable)
		}

		// Create and render package deprecation table
		deprecationTable, hasDeprecationTable := createDeprecationTable(source)
		if hasDeprecationTable {
			renderedDeprecationTable := deprecationTable.Render()
			renderedDeprecationTable = strings.ReplaceAll(renderedDeprecationTable, "\n", "%0A")
			// Sanitize \r to prevent workflow command injection via carriage return in package names
			renderedDeprecationTable = strings.ReplaceAll(renderedDeprecationTable, "\r", "%0D")
			fmt.Fprintf(outputWriter, "::error file=%s::%s%s", artifactPath, artifactPath, "%0A"+renderedDeprecationTable)
		}
	}

	return nil
}
