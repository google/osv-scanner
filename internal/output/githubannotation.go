package output

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
)

// createSourceRemediationTable creates a vulnerability table which includes the fixed versions for a specific source file
func createSourceRemediationTable(source models.PackageSource, groupFixedVersions map[string][]string) table.Writer {
	remediationTable := table.NewWriter()
	remediationTable.AppendHeader(table.Row{"Package", "Vulnerability ID", "CVSS", "Current Version", "Fixed Version"})

	for _, pv := range source.Packages {
		for _, group := range pv.Groups {
			fixedVersions := groupFixedVersions[source.Source.String()+":"+group.IndexString()]

			vulnIDs := []string{}
			for _, id := range group.IDs {
				vulnIDs = append(vulnIDs, "https://osv.dev/"+id)
			}
			remediationTable.AppendRow(table.Row{
				pv.Package.Name,
				strings.Join(vulnIDs, "\n"),
				group.MaxSeverity,
				pv.Package.Version,
				strings.Join(fixedVersions, "\n")})
		}
	}

	return remediationTable
}

// PrintGHAnnotationReport prints Github specific annotations to outputWriter
func PrintGHAnnotationReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	flattened := vulnResult.Flatten()

	// TODO: Also support last affected
	groupFixedVersions := GroupFixedVersions(flattened)
	workingDir := mustGetWorkingDirectory()

	for _, source := range vulnResult.Results {
		// TODO: Support docker images

		var artifactPath string
		var err error
		artifactPath, err = filepath.Rel(workingDir, source.Source.Path)
		if err != nil {
			artifactPath = source.Source.Path
		}

		remediationTable := createSourceRemediationTable(source, groupFixedVersions)

		renderedTable := remediationTable.Render()
		// This is required as github action annotations must be on the same terminal line
		// so we URL encode the new line character
		renderedTable = strings.ReplaceAll(renderedTable, "\n", "%0A")
		// Prepend the table with a new line to look nicer in the output
		fmt.Fprintf(outputWriter, "::error file=%s::%s%s", artifactPath, artifactPath, "%0A"+renderedTable)
	}

	return nil
}
