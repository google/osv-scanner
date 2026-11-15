package output

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
)

var (
	// escapeGHProperty escapes strings being used as the value of a property (e.g. file=) for a GitHub Actions
	// workflow command, matching the escaping done in actions/toolkit.
	//
	// This escapes:
	//   - "\r" and "\n", so the command remains on one line (preventing a new command from being started)
	//   - "%", so that literal sequences (e.g. %0A) are decoded back to themselves, rather than a newline
	//   - ":", so that "::" cannot be used to end the property list prematurely
	//   - ",", so that additional properties cannot be added
	escapeGHProperty = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	// escapeGHData escapes strings being used as message data for a GitHub Actions workflow command,
	// matching the escaping done in actions/toolkit.
	//
	// This escapes:
	//   - "\r" and "\n", so the command remains on one line (preventing a new command from being started)
	//   - "%", so that literal sequences (e.g. %0A) are decoded back to themselves, rather than a newline
	escapeGHData = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
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

		remediationTable, hasVulnTable := createSourceRemediationTable(source, groupedFixedVersions)
		if hasVulnTable {
			renderedTable := remediationTable.Render()

			// Prepend the table with a new line to look nicer in the output
			fmt.Fprintf(outputWriter, "::error file=%s,line=1::%s\n",
				escapeGHProperty.Replace(artifactPath),
				escapeGHData.Replace(artifactPath+"\n"+renderedTable),
			)
		}

		// Create and render package deprecation table
		deprecationTable, hasDeprecationTable := createDeprecationTable(source)
		if hasDeprecationTable {
			renderedDeprecationTable := deprecationTable.Render()

			fmt.Fprintf(outputWriter, "::error file=%s,line=1::%s\n",
				escapeGHProperty.Replace(artifactPath),
				escapeGHData.Replace(artifactPath+"\n"+renderedDeprecationTable),
			)
		}
	}

	return nil
}
