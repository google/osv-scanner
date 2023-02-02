package output

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osv"

	"github.com/jedib0t/go-pretty/v6/table"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintMarkdownTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable.AppendHeader(table.Row{"OSV URL", "Ecosystem", "Package", "Version", "Source"})

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
					links = append(links, osv.BaseVulnerabilityURL+vuln)
				}

				outputRow = append(outputRow, strings.Join(links, " <br>"))

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
	outputTable.RenderMarkdown()
}
