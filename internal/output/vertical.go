package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/jedib0t/go-pretty/v6/text"
)

func PrintVerticalResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) {
	// Add a newline to separate results from logs.
	fmt.Fprintln(outputWriter)
	outputResult := BuildResults(vulnResult)
	printSummary(outputResult, outputWriter)
	if outputResult.IsContainerScanning {
		printBaseImages(outputResult.ImageInfo, outputWriter)
	}

	for i, ecosystem := range outputResult.Ecosystems {
		fmt.Fprintf(outputWriter, "%s", text.FgGreen.Sprintf("%s\n\n", ecosystem.Name))
		for j, source := range ecosystem.Sources {
			printVerticalHeader(source, outputWriter)
			printVerticalVulnerabilities(source, outputResult.IsContainerScanning, outputWriter)
			if j < len(ecosystem.Sources)-1 {
				fmt.Fprintln(outputWriter)
			}
		}

		if i < len(outputResult.Ecosystems)-1 {
			fmt.Fprintln(outputWriter)
		}
	}

	fmt.Fprintln(outputWriter)
}

func printSummary(result Result, out io.Writer) {
	packageForm := Form(result.PackageTypeCount.Regular, "package", "packages")
	vulnerabilityForm := Form(result.VulnTypeSummary.All, "vulnerability", "vulnerabilities")
	fixedVulnForm := Form(result.VulnCount.FixableCount.Fixed, "vulnerability", "vulnerabilities")
	ecosystemForm := Form(len(result.Ecosystems), "ecosystem", "ecosystems")

	summary := fmt.Sprintf(
		"Total %[1]d %[10]s affected by %[2]d known %[11]s (%[3]s, %[4]s, %[5]s, %[6]s, %[7]s) from %[8]s.\n"+
			"%[9]d %[12]s can be fixed.\n",
		result.PackageTypeCount.Regular,
		result.VulnTypeSummary.All,
		text.FgRed.Sprintf("%d Critical", result.VulnCount.SeverityCount.Critical),
		text.FgHiYellow.Sprintf("%d High", result.VulnCount.SeverityCount.High),
		text.FgYellow.Sprintf("%d Medium", result.VulnCount.SeverityCount.Medium),
		text.FgHiCyan.Sprintf("%d Low", result.VulnCount.SeverityCount.Low),
		text.FgCyan.Sprintf("%d Unknown", result.VulnCount.SeverityCount.Unknown),
		text.FgGreen.Sprintf("%d %s", len(result.Ecosystems), ecosystemForm),
		result.VulnCount.FixableCount.Fixed,

		packageForm,
		vulnerabilityForm,
		fixedVulnForm,
	)
	fmt.Fprintln(out, summary)
}

func printBaseImages(imageResult ImageInfo, out io.Writer) {
	fmt.Fprintf(out, "Container image information:\n")
	fmt.Fprintf(out, "  OS version: %s\n", text.FgGreen.Sprintf("%s", imageResult.OS))
	// Calculate the number of digits in the largest layer index
	maxDigits := len(strconv.Itoa(len(imageResult.AllLayers) - 1))
	for _, baseImage := range imageResult.AllBaseImages {
		baseImageString := text.FgYellow.Sprintf("Base Image %d (%s)", baseImage.Index, getBaseImageName(baseImage))
		if baseImage.Index == 0 {
			baseImageString = text.FgYellow.Sprintf("Your Image")
		}
		fmt.Fprintf(out, "  %s:\n", baseImageString)
		for _, layer := range baseImage.AllLayers {
			layerCommand := formatLayerCommand(layer.LayerMetadata.Command)[0]
			layerCommand = truncate(layerCommand, 100)
			fmt.Fprintf(out, "    %s", text.FgCyan.Sprintf("Layer %d", layer.Index))

			// Add spaces for alignment
			padding := strings.Repeat(" ", maxDigits-len(strconv.Itoa(layer.Index)))
			fmt.Fprintf(out, "%s", padding)

			fmt.Fprintf(out, "%s", text.Italic.Sprintf(" %s", layerCommand))
			if layer.Count.AnalysisCount.Regular > 0 {
				fmt.Fprintf(out, " %s\n", text.FgRed.Sprintf("(%d vulns)", layer.Count.AnalysisCount.Regular))
			} else {
				fmt.Fprintln(out)
			}
		}
	}
	fmt.Fprintln(out)
}

func printVerticalHeader(result SourceResult, out io.Writer) {
	fmt.Fprintf(
		out,
		"%s: found %s %s with issues\n",
		text.FgMagenta.Sprintf("%s", result.Name),
		text.FgYellow.Sprintf("%d", result.PackageTypeCount.Regular),
		Form(result.PackageTypeCount.Regular, "package", "packages"),
	)
}

func printVerticalPackageContainerInfo(pkg PackageResult, out io.Writer) {
	baseImageName := getBaseImageName(pkg.LayerDetail.BaseImageInfo)
	fmt.Fprintf(out, "    introduced in %s", text.FgCyan.Sprintf("# %d Layer", pkg.LayerDetail.LayerIndex))
	if baseImageName != "" {
		fmt.Fprintf(out, "%s", text.FgCyan.Sprintf(" (%s)", baseImageName))
	}
	fmt.Fprintln(out)
}

func printVerticalVulnerabilitiesCountSummary(count int, printingCalled bool, sourcePath string, out io.Writer) {
	state := "known"
	if !printingCalled {
		state = "uncalled/unimportant"
	}

	fmt.Fprintf(out, "\n  %s",
		text.FgRed.Sprintf(
			"%d %s %s found in %s",
			count,
			state,
			Form(count, "vulnerability", "vulnerabilities"),
			sourcePath,
		),
	)

	if !printingCalled {
		fmt.Fprintf(out, "%s",
			text.FgRed.Sprint(" (filtered out)"))
	}

	fmt.Fprintln(out)
}

func printVerticalVulnerabilitiesForPackages(packages []PackageResult, out io.Writer, printingCalled bool, isContainerScanning bool) {
	for _, pkg := range packages {
		vulns := pkg.RegularVulns
		if !printingCalled {
			vulns = pkg.HiddenVulns
		}

		if len(vulns) == 0 {
			continue
		}

		state := "known"

		if !printingCalled {
			state = strings.ToLower(getFilteredVulnReasons(vulns))
		}

		fmt.Fprintf(out,
			"  %s %s\n",
			text.FgYellow.Sprintf("%s@%s", pkg.Name, pkg.InstalledVersion),
			text.FgRed.Sprintf("has the following %s vulnerabilities:", state),
		)

		if isContainerScanning {
			printVerticalPackageContainerInfo(pkg, out)
		}

		for _, vulnerability := range vulns {
			fmt.Fprintf(out,
				"    %s %s\n",
				text.FgCyan.Sprintf("%s:", vulnerability.ID),
				describe(vulnerability),
			)
		}
	}
}

func printVerticalVulnerabilities(sourceResult SourceResult, isContainerScanning bool, out io.Writer) {
	countCalled := sourceResult.VulnCount.AnalysisCount.Regular
	countUncalled := sourceResult.VulnCount.AnalysisCount.Hidden

	if countCalled == 0 && countUncalled == 0 {
		fmt.Fprintf(
			out,
			"  %s\n",
			text.FgGreen.Sprintf("no known vulnerabilities found"),
		)

		return
	}

	if countCalled > 0 {
		fmt.Fprintln(out)

		printVerticalVulnerabilitiesForPackages(sourceResult.Packages, out, true, isContainerScanning)
		printVerticalVulnerabilitiesCountSummary(countCalled, true, sourceResult.Name, out)
	}

	if countUncalled > 0 {
		fmt.Fprintln(out)

		printVerticalVulnerabilitiesForPackages(sourceResult.Packages, out, false, isContainerScanning)
		printVerticalVulnerabilitiesCountSummary(countUncalled, false, sourceResult.Name, out)
	}
}

// truncate ensures that the given string is shorter than the provided limit.
//
// If the string is longer than the limit, it's trimmed and suffixed with an ellipsis.
// Ideally the string will be trimmed at the space that's closest to the limit to
// preserve whole words; if a string has no spaces before the limit, it'll be forcefully truncated.
func truncate(str string, limit int) string {
	count := 0
	truncateAt := -1

	for i, c := range str {
		if unicode.IsSpace(c) {
			truncateAt = i
		}

		count++

		if count >= limit {
			// ideally we want to keep words whole when truncating,
			// but if we can't find a space just truncate at the limit
			if truncateAt == -1 {
				truncateAt = limit
			}

			return str[:truncateAt] + "..."
		}
	}

	return str
}

func describe(vulnerability VulnResult) string {
	description := vulnerability.Description
	if description == "" {
		description += "(no details available)"
	} else {
		description = truncate(vulnerability.Description, 80)
	}

	description += " (" + OSVBaseVulnerabilityURL + vulnerability.ID + ")"

	return description
}
