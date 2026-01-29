package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/url"
	"github.com/google/osv-scanner/v2/internal/utility/results"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/internal/utility/vulns"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

type HelpTemplateData struct {
	ID                    string
	AffectedPackagesTable string
	AffectedPackagePaths  []string
	AliasedVulns          []VulnDescription
	HasFixedVersion       bool
	FixedVersionTable     string
	PathSeparator         string
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

// SARIFTemplate is used as the help text for findings.
//
// Note that double double-quotes are ("") are used to represent a single backtick (`)`,
// since backticks cannot be escaped in raw strings
const SARIFTemplate = `
**Your dependency is vulnerable to [{{.ID}}](https://osv.dev/{{.ID}})**
{{- if gt (len .AliasedVulns) 1 }}
(Also published as: {{range .AliasedVulns -}} {{if ne .ID $.ID -}} [{{.ID}}](https://osv.dev/{{.ID}}), {{end}}{{end}})
{{- end}}.

{{range .AliasedVulns -}}
## [{{.ID}}](https://osv.dev/{{.ID}})

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
""{{.}}{{$.PathSeparator}}osv-scanner.toml""

""""""
[[IgnoredVulns]]
id = "{{$.ID}}"
reason = "Your reason for ignoring this vulnerability"
""""""
{{end}}
`

// createSARIFAffectedPkgTable creates a vulnerability table which includes the affected versions for a specific source file
func createSARIFAffectedPkgTable(pkgWithSrc []pkgWithSource) table.Writer {
	helpTable := table.NewWriter()
	headerRow := table.Row{"Source", "Package Name", "Package Version"}

	hasDeprecated := false
	for _, ps := range pkgWithSrc {
		if ps.Package.Deprecated {
			hasDeprecated = true
			break
		}
	}

	if hasDeprecated {
		headerRow = append(headerRow, "Deprecated")
	}
	helpTable.AppendHeader(headerRow)

	for _, ps := range pkgWithSrc {
		ver := ps.Package.Version
		if ps.Package.Commit != "" {
			ver = ps.Package.Commit
		}
		row := table.Row{
			ps.Source.String(),
			ps.Package.Name,
			ver,
		}
		if hasDeprecated {
			row = append(row, ps.Package.Deprecated)
		}
		helpTable.AppendRow(row)
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

// createSARIFFingerprint generates a stable fingerprint for a SARIF result
// to help GitHub deduplicate findings across scans.
//
// The fingerprint is computed from three components to ensure uniqueness while maintaining stability:
//  1. vulnID: The vulnerability identifier (e.g., "CVE-2022-24713") - ensures different vulnerabilities
//     produce different fingerprints even for the same package
//  2. artifactPath: The path to the lockfile (e.g., "/path/to/package.json") - distinguishes the same
//     vulnerability in different parts of a monorepo or different projects
//  3. pkg: The package information (name, version, or commit) - differentiates the same vulnerability
//     across different versions or instances of a package
//
// These three components are combined because they uniquely identify a specific vulnerability finding:
// the same vulnerability (vulnID) in the same package (pkg) detected in the same location (artifactPath)
// should always be considered the same finding and produce the same fingerprint across scans.
func createSARIFFingerprint(vulnID string, artifactPath string, pkg models.PackageInfo) string {
	// Create a stable string representation
	pkgStr := results.PkgToString(pkg)
	fingerprintData := fmt.Sprintf("%s:%s:%s", vulnID, artifactPath, pkgStr)

	// Hash the data to create a stable fingerprint
	hash := sha256.Sum256([]byte(fingerprintData))

	return hex.EncodeToString(hash[:])
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
		if v == nil {
			continue
		}
		for p, v2 := range vulns.GetFixedVersions(v) {
			slices.Sort(v2)
			fixedPkgTableData = append(fixedPkgTableData, FixedPkgTableData{
				PackageName:  p.Name,
				FixedVersion: strings.Join(slices.Compact(v2), ", "),
				VulnID:       v.GetId(),
			})
			hasFixedVersion = true
		}

		vulnDescriptions = append(vulnDescriptions, VulnDescription{
			ID:      v.GetId(),
			Details: strings.ReplaceAll(v.GetDetails(), "\n", "\n> "),
		})
	}
	slices.SortFunc(vulnDescriptions, func(a, b VulnDescription) int { return identifiers.IDSortFunc(a.ID, b.ID) })

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
		PathSeparator:         string(filepath.Separator),
	})

	if err != nil {
		log.Panicf("failed to execute sarif help text template")
	}

	return helpText.String()
}

// PrintSARIFReport prints SARIF output to outputWriter
func PrintSARIFReport(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	report := sarif.NewReport()

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
		if gv == nil {
			continue
		}

		helpText := createSARIFHelpText(gv)

		// Pick the "best" description from the alias group based on the source.
		// Set short description to the first entry with a non-empty summary
		// Set long description to the same entry as short description
		// or use a random long description.
		var shortDescription, longDescription string
		ids := slices.Clone(gv.AliasedIDList)
		slices.SortFunc(ids, identifiers.IDSortFuncForDescription)

		for _, id := range ids {
			v := gv.AliasedVulns[id]
			if v == nil {
				continue
			}
			longDescription = v.GetDetails()
			if v.GetSummary() != "" {
				shortDescription = fmt.Sprintf("%s: %s", gv.DisplayID, v.GetSummary())
				break
			}
		}

		// If no advisory for this vulnerability has a summary field,
		// just show the ID in the shortDescription
		if shortDescription == "" {
			shortDescription = gv.DisplayID
		}

		rule := run.AddRule(gv.DisplayID)
		if rule == nil {
			// Skipping SARIF rule for empty ID
			continue
		}
		rule.WithName(gv.DisplayID).
			WithShortDescription(sarif.NewMultiformatMessageString().WithText(shortDescription).WithMarkdown(shortDescription)).
			WithFullDescription(sarif.NewMultiformatMessageString().WithText(longDescription).WithMarkdown(longDescription)).
			WithMarkdownHelp(helpText)

		// Find the worst severity score
		var worstScore float64 = -1
		for _, v := range gv.AliasedVulns {
			if v == nil || v.GetSeverity() == nil {
				continue
			}
			score, _, _ := severity.CalculateOverallScore(v.GetSeverity())
			if score > worstScore {
				worstScore = score
			}
		}

		if worstScore >= 0 {
			var bag = sarif.NewPropertyBag()
			bag.Add("security-severity", strconv.FormatFloat(worstScore, 'f', -1, 64))
			rule.WithProperties(bag)
		}

		if gv.AliasedIDList == nil {
			gv.AliasedIDList = []string{}
		}
		rule.DeprecatedIds = gv.AliasedIDList

		for _, pws := range gv.PkgSource.StableKeys() {
			artifactPath := stripGitHubWorkspace(pws.Source.Path)
			if filepath.IsAbs(artifactPath) {
				// this only errors if the file path is not absolute,
				// which we've already confirmed is not the case
				p, err := url.FromFilePath(artifactPath)
				if err == nil && p != nil {
					artifactPath = p.String()
				}
			}

			run.AddDistinctArtifact(artifactPath)

			alsoKnownAsStr := ""
			if len(gv.AliasedIDList) > 1 {
				alsoKnownAsStr = fmt.Sprintf(" (also known as '%s')", strings.Join(gv.AliasedIDList[1:], "', '"))
			}

			// Generate a stable fingerprint for deduplication
			fingerprint := createSARIFFingerprint(gv.DisplayID, artifactPath, pws.Package)

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
					)).
				WithPartialFingerprints(map[string]string{
					// Use "primaryLocationLineHash" as the key for the fingerprint.
					// This is the standard key that GitHub Advanced Security uses to deduplicate
					// code scanning alerts across multiple runs.
					//
					// Reference: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#preventing-duplicate-alerts-using-fingerprints
					//
					// GitHub's documentation states: "GitHub uses the primaryLocationLineHash property
					// to detect results that are logically the same, so they can be shown only once,
					// in the correct branch and pull request."
					//
					// For dependency scanning (as opposed to source code analysis), we don't have
					// line numbers in the traditional sense, so our fingerprint is based on the
					// combination of vulnerability ID, package, and location rather than source code lines.
					"primaryLocationLineHash": fingerprint,
				})
		}
	}

	report.AddRun(run)

	err := report.PrettyWrite(outputWriter)
	if err != nil {
		return err
	}
	fmt.Fprintln(outputWriter)

	return nil
}
