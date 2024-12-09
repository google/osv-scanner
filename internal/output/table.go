package output

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/google/osv-scanner/internal/utility/results"
	"github.com/google/osv-scanner/internal/utility/severity"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// OSVBaseVulnerabilityURL is the base URL for detailed vulnerability views.
// Copied in from osv package to avoid referencing the osv package unnecessarily
const OSVBaseVulnerabilityURL = "https://osv.dev/"

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, terminalWidth int) {
	if terminalWidth <= 0 {
		text.DisableColors()
	}

	outputResult := BuildResults(vulnResult)

	// Render the vulnerabilities.
	if outputResult.IsContainerScanning {
		printContainerScanningResult(outputResult, outputWriter, terminalWidth)
	} else {
		outputTable := newTable(outputWriter, terminalWidth)
		outputTable = tableBuilder(outputTable, vulnResult)
		if outputTable.Length() != 0 {
			outputTable.Render()
		}
	}

	// Render the licenses if any.
	outputLicenseTable := newTable(outputWriter, terminalWidth)
	outputLicenseTable = licenseTableBuilder(outputLicenseTable, vulnResult)
	if outputLicenseTable.Length() == 0 {
		return
	}
	outputLicenseTable.Render()
}

func newTable(outputWriter io.Writer, terminalWidth int) table.Writer {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)

	// use fancy characters if we're outputting to a terminal
	if terminalWidth > 0 {
		outputTable.SetStyle(table.StyleRounded)
		outputTable.SetAllowedRowLength(terminalWidth)
	}

	outputTable.Style().Options.DoNotColorBordersAndSeparators = true
	outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgHiBlack}
	outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.BgBlack}

	return outputTable
}

func tableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	outputTable.AppendHeader(table.Row{"OSV URL", "CVSS", "Ecosystem", "Package", "Version", "Source"})
	rows := tableBuilderInner(vulnResult, true, false)
	for _, elem := range rows {
		outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
	}

	uncalledRows := tableBuilderInner(vulnResult, false, false)
	if len(uncalledRows) != 0 {
		outputTable.AppendSeparator()
		outputTable.AppendRow(table.Row{"Uncalled vulnerabilities"})
		outputTable.AppendSeparator()

		for _, elem := range uncalledRows {
			outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
		}
	}

	unimportantRows := tableBuilderInner(vulnResult, true, true)
	if len(unimportantRows) != 0 {
		outputTable.AppendSeparator()
		outputTable.AppendRow(table.Row{"Unimportant vulnerabilities"})
		outputTable.AppendSeparator()

		for _, elem := range unimportantRows {
			outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
		}
	}

	return outputTable
}

func printContainerScanningResult(result Result, outputWriter io.Writer, terminalWidth int) {
	summary := fmt.Sprintf(
		"Total %[1]d packages affected by %[2]d vulnerabilities (%[3]d Critical, %[4]d High, %[5]d Medium, %[6]d Low, %[7]d Unknown) from %[8]d ecosystems.\n"+
			"%[9]d vulnerabilities have fixes available.",
		result.PackageTypeCount.Regular,
		result.VulnTypeSummary.All,
		result.VulnCount.SeverityCount.Critical,
		result.VulnCount.SeverityCount.High,
		result.VulnCount.SeverityCount.Medium,
		result.VulnCount.SeverityCount.Low,
		result.VulnCount.SeverityCount.Unknown,
		len(result.Ecosystems),
		result.VulnCount.FixableCount.Fixed,
	)
	fmt.Fprintln(outputWriter, summary)
	// Add a newline
	fmt.Fprintln(outputWriter)

	for _, ecosystem := range result.Ecosystems {
		fmt.Fprintln(outputWriter, ecosystem.Name)

		for _, source := range ecosystem.Sources {
			outputTable := newTable(outputWriter, terminalWidth)
			outputTable.SetTitle("Source:" + source.Name)
			outputTable.AppendHeader(table.Row{"Package", "Installed Version", "Fix available", "Vuln count"})
			for _, pkg := range source.Packages {
				if pkg.VulnCount.AnalysisCount.Regular == 0 {
					continue
				}
				outputRow := table.Row{}
				totalCount := pkg.VulnCount.AnalysisCount.Regular
				var fixAvailable string
				if pkg.FixedVersion == UnfixedDescription {
					fixAvailable = UnfixedDescription
				} else {
					if pkg.VulnCount.FixableCount.UnFixed > 0 {
						fixAvailable = "Partial fixes Available"
					} else {
						fixAvailable = "Fix Available"
					}
				}
				outputRow = append(outputRow, pkg.Name, pkg.InstalledVersion, fixAvailable, totalCount)
				outputTable.AppendRow(outputRow)
			}
			outputTable.Render()
		}
	}

	if result.VulnTypeSummary.Hidden != 0 {
		// Add a newline
		fmt.Fprintln(outputWriter)
		fmt.Fprintln(outputWriter, "Filtered Vulnerabilities:")
		outputTable := newTable(outputWriter, terminalWidth)
		outputTable.AppendHeader(table.Row{"Package", "Ecosystem", "Installed Version", "Filtered Vuln Count", "Filter Reasons"})
		for _, ecosystem := range result.Ecosystems {
			for _, source := range ecosystem.Sources {
				for _, pkg := range source.Packages {
					if pkg.VulnCount.AnalysisCount.Hidden == 0 {
						continue
					}
					outputRow := table.Row{}
					totalCount := pkg.VulnCount.AnalysisCount.Hidden
					filteredReasons := getFilteredVulnReasons(pkg.HiddenVulns)
					outputRow = append(outputRow, pkg.Name, ecosystem.Name, pkg.InstalledVersion, totalCount, strings.Join(filteredReasons, ", "))
					outputTable.AppendRow(outputRow)
				}
			}
		}
		outputTable.Render()
	}

	// Add a newline
	fmt.Fprintln(outputWriter)

	const promptMessage = "For the most comprehensive scan results, we recommend using the HTML output: " +
		"`osv-scanner --format html --output results.html`.\n" +
		"You can also view the full vulnerability list in your terminal with: " +
		"`osv-scanner --format vertical`."
	fmt.Fprintln(outputWriter, promptMessage)
}

type tbInnerResponse struct {
	row         table.Row
	shouldMerge bool
}

func tableBuilderInner(vulnResult *models.VulnerabilityResults, calledVulns bool, unimportantVulns bool) []tbInnerResponse {
	allOutputRows := []tbInnerResponse{}
	workingDir := mustGetWorkingDirectory()

	for _, sourceRes := range vulnResult.Results {
		for _, pkg := range sourceRes.Packages {
			source := sourceRes.Source
			sourcePath, err := filepath.Rel(workingDir, source.Path)
			if err == nil { // Simplify the path if possible
				source.Path = sourcePath
			}

			// Merge groups into the same row
			for _, group := range pkg.Groups {
				if !(group.IsCalled() == calledVulns && group.IsGroupUnimportant() == unimportantVulns) {
					continue
				}

				outputRow := table.Row{}
				shouldMerge := false

				var links []string

				for _, vuln := range group.IDs {
					links = append(links, OSVBaseVulnerabilityURL+text.Bold.Sprintf("%s", vuln))

					// For container scanning results, if there is a DSA, then skip printing its sub-CVEs.
					if strings.Split(vuln, "-")[0] == "DSA" {
						break
					}
				}

				outputRow = append(outputRow, strings.Join(links, "\n"))
				outputRow = append(outputRow, group.MaxSeverity)

				if pkg.Package.Ecosystem == "" && pkg.Package.Commit != "" {
					pkgCommitStr := results.PkgToString(pkg.Package)
					outputRow = append(outputRow, "GIT", pkgCommitStr, pkgCommitStr)
					shouldMerge = true
				} else {
					name := pkg.Package.Name
					if lockfile.Ecosystem(pkg.Package.Ecosystem).IsDevGroup(pkg.DepGroups) {
						name += " (dev)"
					}
					outputRow = append(outputRow, pkg.Package.Ecosystem, name, pkg.Package.Version)
				}

				outputRow = append(outputRow, source.Path)
				allOutputRows = append(allOutputRows, tbInnerResponse{
					row:         outputRow,
					shouldMerge: shouldMerge,
				})
			}
		}
	}

	return allOutputRows
}

func MaxSeverity(group models.GroupInfo, pkg models.PackageVulns) string {
	var maxSeverity float64 = -1
	for _, vulnID := range group.IDs {
		var severities []models.Severity
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.ID == vulnID {
				severities = vuln.Severity
			}
		}
		score, _, _ := severity.CalculateOverallScore(severities)
		maxSeverity = max(maxSeverity, score)
	}

	if maxSeverity < 0 {
		return ""
	}

	return fmt.Sprintf("%.1f", maxSeverity)
}

func licenseTableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	licenseConfig := vulnResult.ExperimentalAnalysisConfig.Licenses
	if licenseConfig.Summary {
		return licenseSummaryTableBuilder(outputTable, vulnResult)
	} else if len(licenseConfig.Allowlist) > 0 {
		return licenseViolationsTableBuilder(outputTable, vulnResult)
	}

	return outputTable
}

func licenseSummaryTableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	counts := make(map[models.License]int)
	for _, pkgSource := range vulnResult.Results {
		for _, pkg := range pkgSource.Packages {
			for _, l := range pkg.Licenses {
				counts[l] += 1
			}
		}
	}
	if len(counts) == 0 {
		// No packages found.
		return outputTable
	}
	licenses := maps.Keys(counts)
	// Sort the license count in descending count order with the UNKNOWN
	// license last.
	sort.Slice(licenses, func(i, j int) bool {
		if licenses[i] == "UNKNOWN" {
			return false
		}
		if licenses[j] == "UNKNOWN" {
			return true
		}
		if counts[licenses[i]] == counts[licenses[j]] {
			return licenses[i] < licenses[j]
		}

		return counts[licenses[i]] > counts[licenses[j]]
	})
	outputTable.AppendHeader(table.Row{"License", "No. of package versions"})
	for _, license := range licenses {
		outputTable.AppendRow(table.Row{license, counts[license]})
	}

	return outputTable
}

func licenseViolationsTableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	outputTable.AppendHeader(table.Row{"License Violation", "Ecosystem", "Package", "Version", "Source"})
	workingDir := mustGetWorkingDirectory()
	for _, pkgSource := range vulnResult.Results {
		for _, pkg := range pkgSource.Packages {
			if len(pkg.LicenseViolations) == 0 {
				continue
			}
			violations := make([]string, len(pkg.LicenseViolations))
			for i, l := range pkg.LicenseViolations {
				violations[i] = string(l)
			}
			path := pkgSource.Source.Path
			if simplifiedPath, err := filepath.Rel(workingDir, pkgSource.Source.Path); err == nil {
				path = simplifiedPath
			}
			outputTable.AppendRow(table.Row{
				strings.Join(violations, ", "),
				pkg.Package.Ecosystem,
				pkg.Package.Name,
				pkg.Package.Version,
				path,
			})
		}
	}

	return outputTable
}
