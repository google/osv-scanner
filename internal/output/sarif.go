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

type groupedVulns struct {
	DisplayID    string
	PkgSource    map[models.PkgWithSource]struct{}
	AliasedVulns map[string]models.Vulnerability
}

const SARIFTemplate = `
**Your dependency is vulnerable to [{{.ID}}](https://osv.dev/vulnerability/{{.ID}}).**

{{range .AliasedVulns}}
> ## {{.ID}}
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
func CreateSARIFHelpTable(pkgWithSrc map[models.PkgWithSource]struct{}) table.Writer {
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

// idSortFunc sorts IDs ascending by CVE < [ECO-SPECIFIC] < GHSA
func idSortFunc(a, b string) int {
	aIsCVE := strings.HasPrefix(strings.ToUpper(a), "CVE")
	bIsCVE := strings.HasPrefix(strings.ToUpper(b), "CVE")
	if aIsCVE || bIsCVE {
		if aIsCVE == bIsCVE {
			// Both are CVEs, order by alphanumerically
			return strings.Compare(a, b)
		} else if aIsCVE {
			// Only aIsCVE
			return -1
		} else {
			// Only bIsCVE
			return 1
		}
	}

	// Neither is CVE
	aIsGHSA := strings.HasPrefix(strings.ToUpper(a), "GHSA")
	bIsGHSA := strings.HasPrefix(strings.ToUpper(b), "GHSA")
	if aIsGHSA || bIsGHSA {
		if aIsCVE == bIsCVE {
			// Both are CVEs, order by alphanumerically
			return strings.Compare(a, b)
		} else if aIsCVE {
			// Only aIsGHSA // 1, and -1 are intentionally swapped from CVEs
			return 1
		} else {
			// Only bIsGHSA
			return -1
		}
	}

	// Neither is GHSA
	return strings.Compare(a, b)
}

func groupByVulnGroups(vulns *models.VulnerabilityResults) map[string]*groupedVulns {
	// Map of Vuln IDs to
	results := map[string]*groupedVulns{}

	for _, res := range vulns.Results {
		for _, pkg := range res.Packages {
			for _, gi := range pkg.Groups {
				var data *groupedVulns
				// See if this vulnerability group already exists (from another package or source)
				for _, id := range gi.IDs {
					existingData, ok := results[id]
					if ok {
						data = existingData
						break
					}
				}
				// If not create this group
				if data == nil {
					data = &groupedVulns{
						DisplayID:    slices.MinFunc(gi.IDs, idSortFunc),
						PkgSource:    make(map[models.PkgWithSource]struct{}),
						AliasedVulns: make(map[string]models.Vulnerability),
					}
				} else {
					// Edge case can happen here where vulnerabilities in an alias group affect different packages
					// And that the vuln of one package happen to have a higher priority DisplayID, it will not be selected.
					//
					// This line fixes that
					data.DisplayID = slices.MinFunc(append(gi.IDs, data.DisplayID), idSortFunc)
				}
				// Point all the IDs of the same group to the same data, either newly created or existing
				for _, id := range gi.IDs {
					results[id] = data
				}
			}
			for _, v := range pkg.Vulnerabilities {
				newPkgSource := models.PkgWithSource{
					Package: pkg.Package,
					Source:  res.Source,
				}
				entry := results[v.ID]
				entry.PkgSource[newPkgSource] = struct{}{}
				entry.AliasedVulns[v.ID] = v
			}
		}
	}

	return results
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

	vulnIdMap := groupByVulnGroups(vulnResult)

	for _, pv := range vulnIdMap {
		helpTable := CreateSARIFHelpTable(pv.PkgSource)

		helpTextTemplate, err := template.New("helpText").Parse(SARIFTemplate)
		if err != nil {
			log.Panicf("failed to parse sarif help text template")
		}

		allAliasIDs := []string{}
		vulnDescriptions := []VulnDescription{}
		for _, v := range pv.AliasedVulns {
			vulnDescriptions = append(vulnDescriptions, VulnDescription{
				ID:      v.ID,
				Details: strings.ReplaceAll(v.Details, "\n", "\n> "),
			})
			allAliasIDs = append(allAliasIDs, v.ID)
		}

		helpText := strings.Builder{}

		err = helpTextTemplate.Execute(&helpText, HelpTemplateData{
			ID:                    pv.DisplayID,
			AffectedPackagesTable: helpTable.RenderMarkdown(),
			AliasedVulns:          vulnDescriptions,
		})

		if err != nil {
			log.Panicf("failed to execute sarif help text template")
		}

		// Set short description to the first entry with a non empty summary
		// Set long description to the same entry as short description
		// or use a random long description.
		var shortDescription, longDescription string
		for _, v := range pv.AliasedVulns {
			longDescription = v.Details
			if v.Summary != "" {
				shortDescription = v.Summary
				break
			}
		}

		pb := sarif.NewPropertyBag()
		pb.Add("deprecatedIds", allAliasIDs)

		run.AddRule(pv.DisplayID).
			WithShortDescription(sarif.NewMultiformatMessageString(shortDescription)).
			WithFullDescription(sarif.NewMultiformatMessageString(longDescription).WithMarkdown(longDescription)).
			WithMarkdownHelp(helpText.String()).
			WithTextHelp(helpText.String()).AttachPropertyBag(pb)

		for pws := range pv.PkgSource {
			var artifactPath string
			artifactPath, err = filepath.Rel(workingDir, pws.Source.Path)
			if err != nil {
				artifactPath = pws.Source.Path
			}
			run.AddDistinctArtifact(artifactPath)

			run.CreateResultForRule(pv.DisplayID).
				WithLevel("warning").
				WithMessage(
					sarif.NewTextMessage(
						fmt.Sprintf(
							"Package '%s@%s' is vulnerable to '%s' (also known as '%s')",
							pws.Package.Name,
							pws.Package.Version,
							pv.DisplayID,
							strings.Join(allAliasIDs, "', '")))).
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
