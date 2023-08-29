package output

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
)

type HelpTemplateData struct {
	ID                    string
	AffectedPackagesTable string
	Details               string
}

const SARIFTemplate = `
**Your dependency is vulnerable to [{{.ID}}](https://osv.dev/vulnerability/{{.ID}}).**

> ## {{.ID}}
> 
> {{.Details}}
> 

---

### Affected Packages
{{.AffectedPackagesTable}}

`

// GroupFixedVersions builds the fixed versions for each ID Group, with keys formatted like so:
// `Source:ID`
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
	remediationTable.AppendHeader(table.Row{"Package", "Vulnerability ID", "CVSS", "Current Version", "Fixed Version"})

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
				MaxSeverity(group, pv),
				pv.Package.Version,
				strings.Join(fixedVersions, "\n")})
		}
	}

	return remediationTable
}

// CreateSourceRemediationTable creates a vulnerability table which includes the fixed versions for a specific source file
func CreateSARIFHelpTable(pkgWithSrc []models.PkgWithSource) table.Writer {
	helpTable := table.NewWriter()
	helpTable.AppendHeader(table.Row{"Source", "Package Name", "Package Version"})

	for _, ps := range pkgWithSrc {
		helpTable.AppendRow(table.Row{
			ps.Source.String(),
			ps.Package.Name,
			ps.Package.Version,
		})
	}

	return helpTable
}

// PrintSARIFReport prints SARIF output to outputWriter
func PrintSARIFReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("osv-scanner", "https://github.com/google/osv-scanner")
	// run.Tool.Driver.WithVersion()

	workingDir, err := os.Getwd()
	if err != nil {
		log.Panicf("can't get working dir: %v", err)
	}

	vulnIdMap := vulnResult.GroupByVulnerability()

	for _, pv := range vulnIdMap {
		helpTable := CreateSARIFHelpTable(pv.PkgSource)

		helpTextTemplate, err := template.New("helpText").Parse(SARIFTemplate)
		if err != nil {
			log.Panicf("failed to parse sarif help text template")
		}

		helpText := strings.Builder{}

		err = helpTextTemplate.Execute(&helpText, HelpTemplateData{
			ID:                    pv.Vuln.ID,
			AffectedPackagesTable: helpTable.RenderMarkdown(),
			Details:               strings.ReplaceAll(pv.Vuln.Details, "\n", "\n> "),
		})

		if err != nil {
			log.Panicf("failed to execute sarif help text template")
		}

		run.AddRule(pv.Vuln.ID).
			WithShortDescription(sarif.NewMultiformatMessageString(fmt.Sprintf("%s: %s", pv.Vuln.ID, pv.Vuln.Summary))).
			WithFullDescription(sarif.NewMultiformatMessageString(pv.Vuln.Details).WithMarkdown(pv.Vuln.Details)).
			WithMarkdownHelp(helpText.String()).
			WithTextHelp(helpText.String())

		for _, pws := range pv.PkgSource {
			var artifactPath string
			artifactPath, err = filepath.Rel(workingDir, pws.Source.Path)
			if err != nil {
				artifactPath = pws.Source.Path
			}
			run.AddDistinctArtifact(artifactPath)

			run.CreateResultForRule(pv.Vuln.ID).
				WithLevel("warning").
				WithMessage(sarif.NewTextMessage(fmt.Sprintf("Package '%s@%s' is vulnerable to '%s', please upgrade to versions '%s' to fix this vulnerability", pws.Package.Name, pws.Package.Version, pv.Vuln.ID, strings.Join(pv.Vuln.FixedVersions()[models.Package{
					Ecosystem: models.Ecosystem(pws.Package.Ecosystem),
					Name:      pws.Package.Name,
				}], ", ")))).AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(sarif.NewSimpleArtifactLocation(artifactPath)),
				))
		}
	}

	report.AddRun(run)

	err = report.PrettyWrite(outputWriter)
	if err != nil {
		return err
	}
	fmt.Fprintln(outputWriter)

	return nil
}
