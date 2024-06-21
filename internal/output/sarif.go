package output

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/google/osv-scanner/internal/url"
	"github.com/google/osv-scanner/internal/utility/results"
	"github.com/google/osv-scanner/internal/version"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type HelpTemplateData struct {
	ID                    string
	AffectedPackagesTable string
	AffectedPackagePaths  []string
	AliasedVulns          []VulnDescription
	HasFixedVersion       bool
	FixedVersionTable     string
}

type FixedPkgTableData struct {
	VulnID       string
	PackageName  string
	FixedVersion string
}
type VulnDescription struct {
	ID      string
	Details string
}

// Two double-quotes ("") is replaced with a single backtick (`), since we can't embed backticks in raw strings
const SARIFTemplate = `
**Your dependency is vulnerable to [{{.ID}}](https://osv.dev/list?q={{.ID}})**
{{- if gt (len .AliasedVulns) 1 }}
(Also published as: {{range .AliasedVulns -}} {{if ne .ID $.ID -}} [{{.ID}}](https://osv.dev/vulnerability/{{.ID}}), {{end}}{{end}})
{{- end}}.

{{range .AliasedVulns -}}
## [{{.ID}}](https://osv.dev/vulnerability/{{.ID}})

<details>
<summary>Details</summary>

> {{.Details}}

</details>

{{end -}}
---

### Affected Packages

{{.AffectedPackagesTable}}

## Remediation

{{- if .HasFixedVersion }}

To fix these vulnerabilities, update the vulnerabilities past the listed fixed versions below.

### Fixed Versions

{{.FixedVersionTable}}

{{- end}}

If you believe these vulnerabilities do not affect your code and wish to ignore them, add them to the ignore list in an
""osv-scanner.toml"" file located in the same directory as the lockfile containing the vulnerable dependency.

See the format and more options in our documentation here: https://google.github.io/osv-scanner/configuration/

Add or append these values to the following config files to ignore this vulnerability:

{{range .AffectedPackagePaths -}}
""{{.}}/osv-scanner.toml""

""""""
[[IgnoredVulns]]
id = "{{$.ID}}"
reason = "Your reason for ignoring this vulnerability"
""""""
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
func createSARIFAffectedPkgTable(pkgWithSrc []pkgWithSource) table.Writer {
	helpTable := table.NewWriter()
	helpTable.AppendHeader(table.Row{"Source", "Package Name", "Package Version"})

	for _, ps := range pkgWithSrc {
		version := ps.Package.Version
		if ps.Package.Commit != "" {
			version = ps.Package.Commit
		}
		helpTable.AppendRow(table.Row{
			ps.Source.String(),
			ps.Package.Name,
			version,
		})
	}

	return helpTable
}

// createSARIFFixedPkgTable creates a vulnerability table which includes the fixed versions for a specific source file
func createSARIFFixedPkgTable(fixedPkgTableData []FixedPkgTableData) table.Writer {
	helpTable := table.NewWriter()
	helpTable.AppendHeader(table.Row{"Vulnerability ID", "Package Name", "Fixed Version"})

	slices.SortFunc(fixedPkgTableData, func(a, b FixedPkgTableData) int {
		return strings.Compare(a.VulnID, b.VulnID)
	})

	for _, data := range fixedPkgTableData {
		helpTable.AppendRow(table.Row{
			data.VulnID,
			data.PackageName,
			data.FixedVersion,
		})
	}

	return helpTable
}

// stripGitHubWorkspace strips /github/workspace/ from the given path.
func stripGitHubWorkspace(path string) string {
	return strings.TrimPrefix(path, "/github/workspace/")
}

// createSARIFHelpText returns the text for SARIF rule's help field
func createSARIFHelpText(gv *groupedSARIFFinding) string {
	backtickSARIFTemplate := strings.ReplaceAll(strings.TrimSpace(SARIFTemplate), `""`, "`")
	helpTextTemplate, err := template.New("helpText").Parse(backtickSARIFTemplate)
	if err != nil {
		log.Panicf("failed to parse sarif help text template: %v", err)
	}

	vulnDescriptions := []VulnDescription{}
	fixedPkgTableData := []FixedPkgTableData{}

	hasFixedVersion := false
	for _, v := range gv.AliasedVulns {
		for p, v2 := range v.FixedVersions() {
			slices.Sort(v2)
			fixedPkgTableData = append(fixedPkgTableData, FixedPkgTableData{
				PackageName:  p.Name,
				FixedVersion: strings.Join(slices.Compact(v2), ", "),
				VulnID:       v.ID,
			})
			hasFixedVersion = true
		}

		vulnDescriptions = append(vulnDescriptions, VulnDescription{
			ID:      v.ID,
			Details: strings.ReplaceAll(v.Details, "\n", "\n> "),
		})
	}
	slices.SortFunc(vulnDescriptions, func(a, b VulnDescription) int { return idSortFunc(a.ID, b.ID) })

	helpText := strings.Builder{}

	pkgWithSrcKeys := gv.PkgSource.StableKeys()

	affectedPackagePaths := []string{}
	for _, pws := range pkgWithSrcKeys {
		affectedPackagePaths = append(affectedPackagePaths, stripGitHubWorkspace(filepath.Dir(pws.Source.Path)))
	}
	// Compact to remove duplicates
	// (which should already be next to each other since it's sorted in the previous step)
	affectedPackagePaths = slices.Compact(affectedPackagePaths)

	err = helpTextTemplate.Execute(&helpText, HelpTemplateData{
		ID:                    gv.DisplayID,
		AffectedPackagesTable: createSARIFAffectedPkgTable(pkgWithSrcKeys).RenderMarkdown(),
		AliasedVulns:          vulnDescriptions,
		HasFixedVersion:       hasFixedVersion,
		FixedVersionTable:     createSARIFFixedPkgTable(fixedPkgTableData).RenderMarkdown(),
		AffectedPackagePaths:  affectedPackagePaths,
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

		// If no advisory for this vulnerability has a summary field,
		// just show the ID in the shortDescription
		if shortDescription == "" {
			shortDescription = gv.DisplayID
		}

		rule := run.AddRule(gv.DisplayID).
			WithName(gv.DisplayID).
			WithShortDescription(sarif.NewMultiformatMessageString(shortDescription)).
			WithFullDescription(sarif.NewMultiformatMessageString(longDescription).WithMarkdown(longDescription)).
			WithMarkdownHelp(helpText).
			WithTextHelp(helpText)

		rule.DeprecatedIds = gv.AliasedIDList

		for _, pws := range gv.PkgSource.StableKeys() {
			artifactPath := stripGitHubWorkspace(pws.Source.Path)
			if filepath.IsAbs(artifactPath) {
				// this only errors if the file path is not absolute,
				// which we've already confirmed is not the case
				p, _ := url.FromFilePath(artifactPath)

				artifactPath = p.String()
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
							"Package '%s' is vulnerable to '%s'%s.",
							results.PkgToString(pws.Package),
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
