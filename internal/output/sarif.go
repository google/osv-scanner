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
	AliasedVulns          []VulnDescription
}

type VulnDescription struct {
	ID      string
	Details string
}

const SARIFTemplate = `
**Your dependency is vulnerable to [{{.ID}}](https://osv.dev/vulnerability/{{.ID}})** 
{{if gt (len .AliasedVulns) 1 -}}
(Also published as: {{range .AliasedVulns -}} {{if ne .ID $.ID}} [{{.ID}}](https://osv.dev/vulnerability/{{.ID}}) {{end}}{{end}})
{{- end}}.

{{range .AliasedVulns}}
> ## [{{.ID}}](https://osv.dev/vulnerability/{{.ID}})
> 
> {{.Details}}
> 

{{end}}
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

// createSARIFHelpTable creates a vulnerability table which includes the fixed versions for a specific source file
func createSARIFHelpTable(pkgWithSrc map[pkgWithSource]struct{}) table.Writer {
	helpTable := table.NewWriter()
	helpTable.AppendHeader(table.Row{"Source", "Package Name", "Package Version"})

	for ps := range pkgWithSrc {
		helpTable.AppendRow(table.Row{
			ps.Source.String(),
			ps.Package.Name,
			ps.Package.Version,
		})
	}

	return helpTable
}

// createSARIFHelpText returns the text for SARIF rule's help field
func createSARIFHelpText(gv *groupedVuln) string {
	helpTable := createSARIFHelpTable(gv.PkgSource)

	helpTextTemplate, err := template.New("helpText").Parse(SARIFTemplate)
	if err != nil {
		log.Panicf("failed to parse sarif help text template")
	}

	vulnDescriptions := []VulnDescription{}
	for _, v := range gv.AliasedVulns {
		vulnDescriptions = append(vulnDescriptions, VulnDescription{
			ID:      v.ID,
			Details: strings.ReplaceAll(v.Details, "\n", "\n> "),
		})
	}
	slices.SortFunc(vulnDescriptions, func(a, b VulnDescription) int { return idSortFunc(a.ID, b.ID) })

	helpText := strings.Builder{}

	err = helpTextTemplate.Execute(&helpText, HelpTemplateData{
		ID:                    gv.DisplayID,
		AffectedPackagesTable: helpTable.RenderMarkdown(),
		AliasedVulns:          vulnDescriptions,
	})

	if err != nil {
		log.Panicf("failed to execute sarif help text template")
	}

	return helpText.String()
}

// PrintSARIFReport prints SARIF output to outputWriter
func PrintSARIFReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI("osv-scanner", "https://github.com/google/osv-scanner")
	run.Tool.Driver.WithVersion(OSVVersion)

	workingDir, err := os.Getwd()
	if err != nil {
		log.Panicf("can't get working dir: %v", err)
	}

	vulnIDMap := groupByVulnGroups(vulnResult)

	for _, gv := range vulnIDMap {
		helpText := createSARIFHelpText(gv)

		// Set short description to the first entry with a non empty summary
		// Set long description to the same entry as short description
		// or use a random long description.
		var shortDescription, longDescription string
		for _, v := range gv.AliasedVulns {
			longDescription = v.Details
			if v.Summary != "" {
				shortDescription = v.Summary
				break
			}
		}

		// Set deprecatedIds with every aliased ID
		allAliasIDsMinusDisplay := []string{}
		for _, v := range gv.AliasedVulns {
			if v.ID == gv.DisplayID {
				continue
			}
			allAliasIDsMinusDisplay = append(allAliasIDsMinusDisplay, v.ID)
		}
		pb := sarif.NewPropertyBag()
		pb.Add("deprecatedIds", append(allAliasIDsMinusDisplay, gv.DisplayID))

		run.AddRule(gv.DisplayID).
			WithShortDescription(sarif.NewMultiformatMessageString(shortDescription)).
			WithFullDescription(sarif.NewMultiformatMessageString(longDescription).WithMarkdown(longDescription)).
			WithMarkdownHelp(helpText).
			WithTextHelp(helpText).AttachPropertyBag(pb)

		for pws := range gv.PkgSource {
			var artifactPath string
			artifactPath, err = filepath.Rel(workingDir, pws.Source.Path)
			if err != nil {
				artifactPath = pws.Source.Path
			}
			run.AddDistinctArtifact(artifactPath)

			run.CreateResultForRule(gv.DisplayID).
				WithLevel("warning").
				WithMessage(
					sarif.NewTextMessage(
						fmt.Sprintf(
							"Package '%s@%s' is vulnerable to '%s' (also known as '%s')",
							pws.Package.Name,
							pws.Package.Version,
							gv.DisplayID,
							strings.Join(allAliasIDsMinusDisplay, "', '")))).
				AddLocation(
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
