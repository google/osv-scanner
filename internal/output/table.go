package output

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/osv"
	"github.com/google/osv-scanner/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable.AppendHeader(table.Row{"OSV URL (ID In Bold)", "Ecosystem", "Package", "Version", "Source"})

	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	isTerminal := false
	if err == nil { // If output is a terminal, set max length to width and add styling
		outputTable.SetStyle(table.StyleRounded)
		outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgHiBlack}
		outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.BgBlack}
		outputTable.SetAllowedRowLength(width)
		isTerminal = true
	} // Otherwise use default ascii (e.g. getting piped to a file)

	for _, sourceRes := range vulnResult.Results {
		for _, pkg := range sourceRes.Packages {
			workingDir, err := os.Getwd()
			source := sourceRes.Source
			if err == nil {
				sourcePath, err := filepath.Rel(workingDir, source.Path)
				if err == nil { // Simplify the path if possible
					source.Path = sourcePath
				}
			}

			for _, group := range pkg.Groups {
				outputRow := table.Row{}
				shouldMerge := false

				var ids []string
				var links []string

				for _, vuln := range group.IDs {
					ids = append(ids, vuln)
					if isTerminal {
						links = append(links, osv.BaseVulnerabilityURL+text.Bold.EscapeSeq()+vuln+text.Reset.EscapeSeq())
					} else {
						links = append(links, osv.BaseVulnerabilityURL+vuln)
					}
				}

				outputRow = append(outputRow, strings.Join(links, "\n"))

				if pkg.Package.Ecosystem == "GIT" {
					outputRow = append(outputRow, "GIT", pkg.Package.Version, pkg.Package.Version)
					shouldMerge = true
				} else {
					outputRow = append(outputRow, pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version)
				}

				outputRow = append(outputRow, source.Path)
				outputTable.AppendRow(outputRow, table.RowConfig{AutoMerge: shouldMerge})
			}
		}
	}

	if outputTable.Length() == 0 {
		return
	}
	outputTable.Render()
}
