package output

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv.dev/tools/osv-scanner/internal/grouper"
	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(query osv.BatchedQuery, resp *osv.HydratedBatchedResponse, outputWriter io.Writer) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable.AppendHeader(table.Row{"Source", "Ecosystem", "Affected Package", "Installed Version", "Vulnerability ID", "OSV URL"})

	for i, query := range query.Queries {
		if len(resp.Results[i].Vulns) == 0 {
			continue
		}
		workingDir, err := os.Getwd()
		source := query.Source
		if err == nil {
			sourcePath, err := filepath.Rel(workingDir, query.Source.Path)
			if err == nil { // Simplify the path if possible
				source.Path = sourcePath
			}
		}
		for _, group := range grouper.Group(resp.Results[i].Vulns) {
			outputRow := table.Row{source}
			shouldMerge := false
			if query.Commit != "" {
				outputRow = append(outputRow, "GIT", query.Commit, query.Commit)
				shouldMerge = true
			} else if query.Package.PURL != "" {
				pkg, err := PURLToPackage(query.Package.PURL)
				if err != nil {
					log.Println("Failed to parse purl")
					continue
				}
				outputRow = append(outputRow, pkg.Ecosystem, pkg.Name, pkg.Version)
				shouldMerge = true
			} else {
				outputRow = append(outputRow, query.Package.Ecosystem, query.Package.Name, query.Version)
			}

			var ids []string
			var links []string

			for _, vuln := range group {
				ids = append(ids, vuln.ID)
				links = append(links, osv.BaseVulnerabilityURL+vuln.ID)
			}

			outputRow = append(outputRow, strings.Join(ids, "\n"), strings.Join(links, "\n"))
			outputTable.AppendRow(outputRow, table.RowConfig{AutoMerge: shouldMerge})
		}
	}

	outputTable.SetStyle(table.StyleRounded)
	outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgBlack}
	outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.Reset}

	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil { // If output is a terminal, set max length to width
		outputTable.SetAllowedRowLength(width)
	} // Otherwise don't set max width (e.g. getting piped to a file)
	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
}
