package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
)

// GroupFixedVersions builds the fixed versions for each ID Group
func GroupFixedVersions(flattened []models.VulnerabilityFlattened) map[string][]string {
	groupFixedVersions := map[string][]string{}

	// Get the fixed versions indexed by each group of vulnerabilities
	// Prepend source path as same vulnerability in two projects should be counted twice
	// Remember to sort and compact before displaying later
	for _, vf := range flattened {
		groupIdx := vf.Source.String() + ":" + vf.GroupInfo.IndexString()
		pkg := models.Package{
			Ecosystem: models.Ecosystem(vf.Package.Ecosystem),
			Name:      vf.Package.Name,
		}
		groupFixedVersions[groupIdx] =
			append(groupFixedVersions[groupIdx], vf.Vulnerability.FixedVersions()[pkg]...)
	}

	// Remove duplicates
	for k := range groupFixedVersions {
		fixedVersions := groupFixedVersions[k]
		slices.Sort(fixedVersions)
		groupFixedVersions[k] = slices.Compact(fixedVersions)
	}

	return groupFixedVersions
}

// CreateSourceRemediationTable creates a vulnerability table which includes the fixed versions for a specific source file
func CreateSourceRemediationTable(source models.PackageSource, groupFixedVersions map[string][]string) table.Writer {
	remediationTable := table.NewWriter()
	remediationTable.AppendHeader(table.Row{"Package", "Vulnerability ID", "Current Version", "Fixed Version"})

	for _, pv := range source.Packages {
		for _, group := range pv.Groups {
			fixedVersions := groupFixedVersions[source.Source.String()+":"+group.IndexString()]

			vulnIDs := []string{}
			for _, id := range group.IDs {
				vulnIDs = append(vulnIDs, fmt.Sprintf("https://osv.dev/%s", id))
			}
			remediationTable.AppendRow(table.Row{
				pv.Package.Name,
				strings.Join(vulnIDs, "\n"),
				pv.Package.Version,
				strings.Join(fixedVersions, "\n")})
		}
	}

	return remediationTable
}

// PrintSARIFReport prints SARIF output to outputWriter
func PrintSARIFReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("osv-scanner", "https://github.com/google/osv-scanner")
	run.AddRule("vulnerable-packages").
		WithDescription("This manifest file contains one or more vulnerable packages.")
	flattened := vulnResult.Flatten()

	// TODO: Also support last affected
	groupFixedVersions := GroupFixedVersions(flattened)
	workingDir, workingDirErr := os.Getwd()

	for _, source := range vulnResult.Results {
		// TODO: Support docker images

		var artifactPath string
		if workingDirErr == nil {
			artifactPath, err = filepath.Rel(workingDir, source.Source.Path)
			if err != nil {
				artifactPath = source.Source.Path
			}
		} else {
			artifactPath = source.Source.Path
		}
		run.AddDistinctArtifact(artifactPath)

		remediationTable := CreateSourceRemediationTable(source, groupFixedVersions)

		renderedTable := remediationTable.Render()
		// This is required since the github message rendering is a mixture of
		// monospaced font text and markdown. Continuous spaces will be compressed
		// down to one space, breaking the table rendering
		renderedTable = strings.ReplaceAll(renderedTable, "  ", " &nbsp;")
		run.CreateResultForRule("vulnerable-packages").
			WithLevel("warning").
			WithMessage(sarif.NewMessage().WithText(renderedTable)).
			AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(
							sarif.NewSimpleArtifactLocation(artifactPath))))
	}

	report.AddRun(run)

	err = report.PrettyWrite(outputWriter)
	if err != nil {
		return err
	}
	fmt.Fprintln(outputWriter)

	return nil
}
