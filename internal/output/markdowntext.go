package output

import (
	"fmt"
	"html"
	"io"
	"log"
	"strings"
	"text/template"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"

	"github.com/jedib0t/go-pretty/v6/table"
)

const MarkdownTextTemplate = `
## Vulnerability Summary

From a scan of **{{.ManifestNum}}** project and manifest files, OSV-Scanner:
 - Found **{{.AffectedVulnNum}}** vulnerabilities that are affecting your code.
 - Found an additional **{{.UnaffectedVulnNum}}** vulnerabilities that are not directly affecting your code (does not get called).

{{.SourceTable}}

<details>
	<summary><b>OSV-Scanner Output</b></summary>
	
{{.VulnTable}}
</details>

## Remediation Steps:

**{{.FixableNum}}** vulnerabilities have fixed versions available.

{{range .Sources}}
### {{.Name}}

{{.Table}}

{{end}}
`

type TextOutput struct {
	ManifestNum       int
	AffectedVulnNum   int
	UnaffectedVulnNum int
	SourceTable       string
	VulnTable         string
	FixableNum        int
	Sources           []struct {
		Name  string
		Table string
	}
}

// PrintMarkdownTextResults prints the osv scan results into a human friendly table.
func PrintMarkdownTextResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	// This template does not automatically escape values
	template, err := template.New("Vuln output").Parse(MarkdownTextTemplate)
	if err != nil {
		panic("Template is invalid")
	}

	output := TextOutput{}
	flattened := vulnResult.Flatten()

	output.ManifestNum = len(vulnResult.Results)

	// Count vuln number by iterating over groups
	for _, ps := range vulnResult.Results {
		for _, pkg := range ps.Packages {
			for _, group := range pkg.Groups {
				if group.IsCalled() {
					output.AffectedVulnNum += 1
				} else {
					output.UnaffectedVulnNum += 1
				}
			}
		}
	}

	// Get the fixed versions indexed by each group of vulnerabilities
	groupFixedVersions := map[string][]string{}
	for _, vf := range flattened {
		// Prepend source path as same vulnerability in two projects should be counted twice
		groupIdx := vf.Source.String() + ":" + vf.GroupInfo.IndexString()
		groupFixedVersions[groupIdx] = // Remember to sort and compact before displaying later
			append(groupFixedVersions[groupIdx], vf.Vulnerability.FixedVersions()...)
	}

	// Count fixable vuln number
	for id, val := range groupFixedVersions {
		if len(val) > 0 {
			output.FixableNum += 1
		} else {
			log.Println(id)
		}
	}

	sourceTable := table.NewWriter()

	sourceTable.AppendHeader(table.Row{"Scanned File", "Number of Vulnerabilities"})
	for _, ps := range vulnResult.Results {
		vulnCounter := 0
		for _, packageVulns := range ps.Packages {
			vulnCounter += len(packageVulns.Groups)
		}
		sourceTable.AppendRow(table.Row{html.EscapeString(ps.Source.String()), vulnCounter})
	}

	output.SourceTable = sourceTable.RenderMarkdown()

	outputDetailedTable := table.NewWriter()
	outputDetailedTable.AppendHeader(table.Row{"OSV URL", "Ecosystem", "Package", "Version", "Source"})

	outputDetailedTable = tableBuilder(outputDetailedTable, vulnResult, false)

	output.VulnTable = outputDetailedTable.RenderMarkdown()

	for _, source := range vulnResult.Results {
		remediationTable := table.NewWriter()
		remediationTable.AppendHeader(table.Row{"Package", "Vulnerability ID", "Current Version", "Fixed Version"})

		for _, pv := range source.Packages {
			for _, group := range pv.Groups {
				fixedVersions := groupFixedVersions[source.Source.String()+":"+group.IndexString()]
				// Remove duplicates
				slices.Sort(fixedVersions)
				fixedVersions = slices.Compact(fixedVersions)

				vulnIDs := []string{}
				for _, id := range group.IDs {
					vulnIDs = append(vulnIDs, fmt.Sprintf("[%[1]s](https://osv.dev/vulnerability/%[1]s)", id))
				}
				remediationTable.AppendRow(table.Row{
					pv.Package.Name,
					strings.Join(vulnIDs, "\n"),
					pv.Package.Version,
					strings.Join(fixedVersions, "\n")})
			}
		}

		output.Sources = append(output.Sources, struct {
			Name  string
			Table string
		}{
			Name:  html.EscapeString(source.Source.String()),
			Table: remediationTable.RenderMarkdown(),
		})
	}

	err = template.Execute(outputWriter, output)
	if err != nil {
		panic(err)
	}
}
