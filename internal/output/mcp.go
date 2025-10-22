package output

import (
	"io"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// PrintMCPReport prints a LLM friendly vulnerability report
func PrintMCPReport(vulnResult *models.VulnerabilityResults, additionalInfo []string, outputWriter io.Writer) error {
	stringRes := strings.Builder{}
	stringRes.WriteString(`
Output results are grouped into (Ecosystem -> Source file -> Packages -> Vulnerabilities),
with a title for each section, and indentation to indicate that it belongs to the above section.
When resolving these vulnerabilities, avoid manually updating individual packages, and use system tools.
Use https://osv.dev/vulnerability/<VULN-ID> as the official record of the vulnerability.
Do not attempt to fix vulnerabilities without fix available.

Scan Info:

`)

	for _, s := range additionalInfo {
		stringRes.WriteString(s + "\n")
	}

	stringRes.WriteString("\n")

	outputResult := BuildResults(vulnResult)
	for _, eco := range outputResult.Ecosystems {
		amendString(&stringRes, "Ecosystem: "+eco.Name, 1)
		for _, sources := range eco.Sources {
			amendString(&stringRes, "Source file path: "+sources.Name, 2)
			for _, pkg := range sources.Packages {
				amendString(&stringRes, "Package Name: "+pkg.Name, 3)
				for _, vulns := range pkg.RegularVulns {
					amendString(&stringRes, "Vuln ID: "+vulns.ID+" - Minimum Fix Version: "+vulns.FixedVersion, 4)
				}
			}
		}
	}

	_, err := outputWriter.Write([]byte(stringRes.String()))

	return err
}

func amendString(builder *strings.Builder, value string, indent int) {
	for range indent {
		builder.WriteByte('\t')
	}
	builder.WriteString(value)
	builder.WriteByte('\n')
}
