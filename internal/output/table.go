package output

import (
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"

	v2_metric "github.com/goark/go-cvss/v2/metric"
	v3_metric "github.com/goark/go-cvss/v3/metric"

	"github.com/google/osv-scanner/internal/utility/results"
	"github.com/google/osv-scanner/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// OSVBaseVulnerabilityURL is the base URL for detailed vulnerability views.
// Copied in from osv package to avoid referencing the osv package unnecessarily
const OSVBaseVulnerabilityURL = "https://osv.dev/"

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, terminalWidth int) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable.AppendHeader(table.Row{"OSV URL", "CVSS", "Ecosystem", "Package", "Version", "Source"})

	if terminalWidth > 0 { // If output is a terminal, set max length to width and add styling
		outputTable.SetStyle(table.StyleRounded)
		outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgHiBlack}
		outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.BgBlack}
		outputTable.Style().Options.DoNotColorBordersAndSeparators = true
		outputTable.SetAllowedRowLength(terminalWidth)
	} // Otherwise use default ascii (e.g. getting piped to a file)

	outputTable = tableBuilder(outputTable, vulnResult, terminalWidth > 0)

	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
}

func tableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults, addStyling bool) table.Writer {
	rows := tableBuilderInner(vulnResult, addStyling, true)
	for _, elem := range rows {
		outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
	}

	uncalledRows := tableBuilderInner(vulnResult, addStyling, false)
	if len(uncalledRows) == 0 {
		return outputTable
	}

	outputTable.AppendSeparator()
	outputTable.AppendRow(table.Row{"Uncalled vulnerabilities"})
	outputTable.AppendSeparator()

	for _, elem := range uncalledRows {
		outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
	}

	return outputTable
}

type tbInnerResponse struct {
	row         table.Row
	shouldMerge bool
}

func tableBuilderInner(vulnResult *models.VulnerabilityResults, addStyling bool, calledVulns bool) []tbInnerResponse {
	allOutputRows := []tbInnerResponse{}
	// Working directory used to simplify path
	workingDir, err := os.Getwd()
	if err != nil {
		log.Panicf("can't get working dir: %v", err)
	}
	for _, sourceRes := range vulnResult.Results {
		for _, pkg := range sourceRes.Packages {
			source := sourceRes.Source
			sourcePath, err := filepath.Rel(workingDir, source.Path)
			if err == nil { // Simplify the path if possible
				source.Path = sourcePath
			}

			// Merge groups into the same row
			for _, group := range pkg.Groups {
				if group.IsCalled() != calledVulns {
					continue
				}

				outputRow := table.Row{}
				shouldMerge := false

				var links []string

				for _, vuln := range group.IDs {
					if addStyling {
						links = append(links, OSVBaseVulnerabilityURL+text.Bold.EscapeSeq()+vuln+text.Reset.EscapeSeq())
					} else {
						links = append(links, OSVBaseVulnerabilityURL+vuln)
					}
				}

				outputRow = append(outputRow, strings.Join(links, "\n"))
				outputRow = append(outputRow, MaxSeverity(group, pkg))

				if pkg.Package.Ecosystem == "" && pkg.Package.Commit != "" {
					pkgCommitStr := results.PkgToString(pkg.Package)
					outputRow = append(outputRow, "GIT", pkgCommitStr, pkgCommitStr)
					shouldMerge = true
				} else {
					outputRow = append(outputRow, pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version)
				}

				outputRow = append(outputRow, source.Path)
				allOutputRows = append(allOutputRows, tbInnerResponse{
					row:         outputRow,
					shouldMerge: shouldMerge,
				})
			}
		}
	}

	return allOutputRows
}

func MaxSeverity(group models.GroupInfo, pkg models.PackageVulns) string {
	var maxSeverity float64
	for _, vulnID := range group.IDs {
		var severities []models.Severity
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.ID == vulnID {
				severities = vuln.Severity
			}
		}
		for _, severity := range severities {
			switch severity.Type {
			case models.SeverityCVSSV2:
				numericSeverity, _ := v2_metric.NewBase().Decode(severity.Score)
				maxSeverity = math.Max(maxSeverity, numericSeverity.Score())
			case models.SeverityCVSSV3:
				numericSeverity, _ := v3_metric.NewBase().Decode(severity.Score)
				maxSeverity = math.Max(maxSeverity, numericSeverity.Score())
			}
		}
	}

	if maxSeverity == 0 {
		return ""
	}

	return fmt.Sprintf("%v", maxSeverity)
}
