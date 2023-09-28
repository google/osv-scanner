package output

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/exp/slices"
)

type HelpTemplateData struct {
	ID                    string
	AffectedPackagesTable string
	AliasedVulns          []VulnDescription
	HasFixedVersion       bool
	FixedVersionTable     string
}

type PackageWithFixedVersion struct {
	PackageName  string
	FixedVersion string
}
type VulnDescription struct {
	ID      string
	Details string
}

const SARIFTemplate = `
**Your dependency is vulnerable to [{{.ID}}](https://osv.dev/vulnerability/{{.ID}})**
{{- if gt (len .AliasedVulns) 1 }}
(Also published as: {{range .AliasedVulns -}} {{if ne .ID $.ID}} [{{.ID}}](https://osv.dev/vulnerability/{{.ID}}), {{end}}{{end}})
{{- end}}.

{{range .AliasedVulns}}
## [{{.ID}}](https://osv.dev/vulnerability/{{.ID}})

<details>
<summary>Details</summary>

> {{.Details}}

</details>


{{end}}
---

### Affected Packages
{{.AffectedPackagesTable}}

{{if .HasFixedVersion}}
### Fixed Versions
{{.FixedVersionTable}}
{{end}}
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

// createSARIFAffectedPkgTable creates a vulnerability table which includes the affected versions for a specific source file
func createSARIFAffectedPkgTable(pkgWithSrc map[pkgWithSource]struct{}) table.Writer {
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

// createSARIFFixedPkgTable creates a vulnerability table which includes the fixed versions for a specific source file
func createSARIFFixedPkgTable(pkgWithVulns map[string][]PackageWithFixedVersion) table.Writer {
	helpTable := table.NewWriter()
	helpTable.AppendHeader(table.Row{"Vulnerability ID", "Package Name", "Fixed Version"})

	for id, pkg := range pkgWithVulns {
		for _, pwfv := range pkg {
			helpTable.AppendRow(table.Row{
				id,
				pwfv.PackageName,
				pwfv.FixedVersion,
			})
		}
	}

	return helpTable
}

// stripGitHubWorkspace strips /github/workspace/ from the given path.
func stripGitHubWorkspace(path string) string {
	return strings.TrimPrefix(path, "/github/workspace/")
}

// createSARIFHelpText returns the text for SARIF rule's help field
func createSARIFHelpText(gv *groupedSARIFFinding) string {
	helpTable := createSARIFAffectedPkgTable(gv.PkgSource)

	helpTextTemplate, err := template.New("helpText").Parse(SARIFTemplate)
	if err != nil {
		log.Panicf("failed to parse sarif help text template: %v", err)
	}

	vulnDescriptions := []VulnDescription{}
	vulnFixedVersion := map[string][]PackageWithFixedVersion{}

	hasFixedVersion := false
	for _, v := range gv.AliasedVulns {
		fixedVersions := []PackageWithFixedVersion{}
		for p, v2 := range v.FixedVersions() {
			slices.Sort(v2)
			fixedVersions = append(fixedVersions, PackageWithFixedVersion{
				PackageName:  p.Name,
				FixedVersion: strings.Join(slices.Compact(v2), ", "),
			})
			hasFixedVersion = true
		}
		vulnFixedVersion[v.ID] = fixedVersions

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
		HasFixedVersion:       hasFixedVersion,
		FixedVersionTable:     createSARIFFixedPkgTable(vulnFixedVersion).RenderMarkdown(),
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
	run.Tool.Driver.WithVersion(version.OSVVersion)

	vulnIDMap := mapIDsToGroupedSARIFFinding(vulnResult)
	// Sort the IDs to have deterministic loop of vulnIDMap
	vulnIDs := []string{}
	for vulnID := range vulnIDMap {
		vulnIDs = append(vulnIDs, vulnID)
	}
	slices.Sort(vulnIDs)

	for _, vulnID := range vulnIDs {
		gv := vulnIDMap[vulnID]

		helpText := createSARIFHelpText(gv)

		// Pick the "best" description from the alias group based on the source.
		// Set short description to the first entry with a non empty summary
		// Set long description to the same entry as short description
		// or use a random long description.
		var shortDescription, longDescription string
		ids := slices.Clone(gv.AliasedIDList)
		slices.SortFunc(ids, idSortFuncForDescription)

		for _, id := range ids {
			v := gv.AliasedVulns[id]
			longDescription = v.Details
			if v.Summary != "" {
				shortDescription = fmt.Sprintf("%s: %s", gv.DisplayID, v.Summary)
				break
			}
		}

		rule := run.AddRule(gv.DisplayID).
			WithShortDescription(sarif.NewMultiformatMessageString(shortDescription)).
			WithFullDescription(sarif.NewMultiformatMessageString(longDescription).WithMarkdown(longDescription)).
			WithMarkdownHelp(helpText).
			WithTextHelp(helpText)

		rule.DeprecatedIds = gv.AliasedIDList
		for pws := range gv.PkgSource {
			artifactPath := stripGitHubWorkspace(pws.Source.Path)
			if filepath.IsAbs(artifactPath) {
				// Support absolute paths.
				artifactPath = "file://" + artifactPath
			}

			run.AddDistinctArtifact(artifactPath)

			alsoKnownAsStr := ""
			if len(gv.AliasedIDList) > 1 {
				alsoKnownAsStr = fmt.Sprintf(" (also known as '%s')", strings.Join(gv.AliasedIDList[1:], "', '"))
			}

			run.CreateResultForRule(gv.DisplayID).
				WithLevel("warning").
				WithMessage(
					sarif.NewTextMessage(
						fmt.Sprintf(
							"Package '%s@%s' is vulnerable to '%s'%s.",
							pws.Package.Name,
							pws.Package.Version,
							gv.DisplayID,
							alsoKnownAsStr,
						))).
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
