package output

import (
	"cmp"
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/google/osv-scanner/internal/identifiers"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/internal/utility/severity"
	"github.com/google/osv-scanner/pkg/models"
)

// OutputResult represents the vulnerability scanning results for output report.
type OutputResult struct { //nolint:revive
	Ecosystems []OutputEcosystemResult
	// Container scanning related
	IsContainerScanning bool
	AllLayers           []OutputLayerInfo
	VulnTypeCount       OutputVulnTypeCount
	VulnCount           OutputVulnCount
}

// OutputEcosystemResult represents the vulnerability scanning results for an ecosystem.
type OutputEcosystemResult struct { //nolint:revive
	Name    string
	Sources []OutputSourceResult
	IsOS    bool
}

// OutputSourceResult represents the vulnerability scanning results for a source file.
type OutputSourceResult struct { //nolint:revive
	Name             string
	Ecosystem        string
	PackageTypeCount OutputCallAnalysisCount
	Packages         []OutputPackageResult
	VulnCount        OutputVulnCount
}

// OutputPackageResult represents the vulnerability scanning results for a package.
type OutputPackageResult struct { //nolint:revive
	Name             string
	InstalledVersion string
	FixedVersion     string
	CalledVulns      []OutputVulnResult
	UncalledVulns    []OutputVulnResult
	LayerDetail      OutputPackageLayerDetail
	VulnCount        OutputVulnCount
}

// OutputVulnResult represents a single vulnerability.
type OutputVulnResult struct { //nolint:revive
	ID             string
	GroupIDs       []string
	Aliases        []string
	FixedVersion   string
	SeverityRating string
	SeverityScore  string
}

// OutputPackageLayerDetail represents detailed layer tracing information about a package.
type OutputPackageLayerDetail struct { //nolint:revive
	LayerCommand        string
	LayerCommandTooltip string
	LayerID             string
	InBaseImage         bool
}

type OutputLayerInfo struct { //nolint:revive
	Index        int
	LayerCommand string
	LayerID      string
	Count        OutputVulnCount
}

// OutputVulnCount represents the counts of vulnerabilities by severity and fixed/unfixed status
type OutputVulnCount struct { //nolint:revive
	SeverityCount     OutputSeverityCount
	CallAnalysisCount OutputCallAnalysisCount
	FixableCount      OutputFixableCount
}

type OutputSeverityCount struct { //nolint:revive
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

type OutputVulnTypeCount struct { //nolint:revive
	All      int
	OS       int
	Project  int
	Uncalled int
}

type OutputCallAnalysisCount struct { //nolint:revive
	Called   int
	Uncalled int
}

type OutputFixableCount struct { //nolint:revive
	Fixed   int
	UnFixed int
}

// PrintOutputResults prints the output to the outputWriter.
// This function is for testing purposes only, to visualize the result format.
func PrintOutputResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	result := BuildOutputResults(vulnResult)
	//nolint:musttag
	return encoder.Encode(result)
}

// BuildOutputResults constructs the output result structure from the vulnerability results.
//
// This function creates a hierarchical representation of the results, starting from the overall
// summary and drilling down to ecosystems, sources, packages, and vulnerability details.
// This structured format facilitates generating various output formats (e.g., table, HTML, etc.).
func BuildOutputResults(vulnResult *models.VulnerabilityResults) OutputResult {
	var ecosystemMap = make(map[string][]OutputSourceResult)
	var resultCount OutputVulnCount

	for _, packageSource := range vulnResult.Results {
		// Temporary workaround: it is a heuristic to ignore installed packages
		// which are already covered by OS-specific vulnerabilities.
		// This filtering should be handled by the container scanning process.
		// TODO(gongh@): Revisit this after container scanning supports comprehensive functionality.
		if strings.Contains(packageSource.Source.String(), "/usr/lib/") {
			continue
		}

		// Process vulnerabilities for each source
		sourceResult := processOutputSource(packageSource)
		ecosystemMap[sourceResult.Ecosystem] = append(ecosystemMap[sourceResult.Ecosystem], sourceResult)
		resultCount = updateVulnCount(resultCount, sourceResult.VulnCount)
	}

	// Build the final result
	return buildOutputResult(ecosystemMap, resultCount)
}

// buildOutputResult builds the final OutputResult object from the ecosystem map and total vulnerability count.
func buildOutputResult(ecosystemMap map[string][]OutputSourceResult, resultCount OutputVulnCount) OutputResult {
	var ecosystemResults []OutputEcosystemResult
	var osResults []OutputEcosystemResult
	for ecosystem, sources := range ecosystemMap {
		ecosystemResult := OutputEcosystemResult{
			Name:    ecosystem,
			Sources: sources,
		}

		if isOSEcosystem(ecosystem) {
			ecosystemResult.IsOS = true
			osResults = append(osResults, ecosystemResult)
		} else {
			ecosystemResults = append(ecosystemResults, ecosystemResult)
		}
	}

	// Sort ecosystemResults to ensure consistent output
	slices.SortFunc(ecosystemResults, func(a, b OutputEcosystemResult) int {
		return cmp.Compare(a.Name, b.Name)
	})

	// Sort osResults to ensure consistent output
	slices.SortFunc(osResults, func(a, b OutputEcosystemResult) int {
		return cmp.Compare(a.Name, b.Name)
	})

	// Add project results before OS results
	ecosystemResults = append(ecosystemResults, osResults...)

	isContainerScanning := false
	layers := getAllLayerInfo(ecosystemResults)
	if len(layers) > 0 {
		isContainerScanning = true
	}
	vulnTypeCount := getOutputVulnTypeCount(ecosystemResults)

	return OutputResult{
		Ecosystems:          ecosystemResults,
		VulnTypeCount:       vulnTypeCount,
		VulnCount:           resultCount,
		IsContainerScanning: isContainerScanning,
		AllLayers:           layers,
	}
}

// processOutputSource processes a single source (lockfile or artifact) and returns an SourceResult.
func processOutputSource(packageSource models.PackageSource) OutputSourceResult {
	var sourceResult OutputSourceResult
	packages := make([]OutputPackageResult, 0)
	packageMap := make(map[string]bool)
	ecosystemName := ""

	for _, vulnPkg := range packageSource.Packages {
		if ecosystemName == "" {
			ecosystemName = vulnPkg.Package.Ecosystem
		}
		key := vulnPkg.Package.Name + ":" + vulnPkg.Package.Version
		if _, exist := packageMap[key]; exist {
			// In container scanning, the same package (same name and version) might be found multiple times
			// within a single source. This happens because we use the upstream source name instead of
			// the Linux distribution package name.
			continue
		}
		packageResult := processOutputPackage(vulnPkg)
		packages = append(packages, packageResult)

		sourceResult.VulnCount = updateVulnCount(sourceResult.VulnCount, packageResult.VulnCount)
		if len(packageResult.CalledVulns) != 0 {
			sourceResult.PackageTypeCount.Called += 1
		}
		// A package can be counted as both called and uncalled if it has both called and uncalled vulnerabilities.
		if len(packageResult.UncalledVulns) != 0 {
			sourceResult.PackageTypeCount.Uncalled += 1
		}
	}
	// Sort packageResults to ensure consistent output
	slices.SortFunc(packages, func(a, b OutputPackageResult) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.InstalledVersion, b.InstalledVersion),
		)
	})
	sourceResult.Name = packageSource.Source.String()
	sourceResult.Packages = packages
	sourceResult.Ecosystem = ecosystemName

	return sourceResult
}

// processOutputPackage processes vulnerability information for a given package
// and generates a structured output result.
//
// This function processes the vulnerability groups, updates vulnerability details,
// and constructs the final output result for the package, including details about
// called and uncalled vulnerabilities, fixable counts, and layer information (if available).
func processOutputPackage(vulnPkg models.PackageVulns) OutputPackageResult {
	calledVulnMap, uncalledVulnMap, count := processOutputVulnerabilityGroups(vulnPkg)
	updateVulnerabilityDetails(vulnPkg, calledVulnMap, &count)
	updateVulnerabilityDetails(vulnPkg, uncalledVulnMap, &count)

	calledVulnList := getVulnList(calledVulnMap)
	uncalledVulnList := getVulnList(uncalledVulnMap)

	packageFixedVersion := getPackageFixedVersion(vulnPkg.Package.Ecosystem, calledVulnList)

	packageResult := OutputPackageResult{
		Name:             vulnPkg.Package.Name,
		InstalledVersion: vulnPkg.Package.Version,
		FixedVersion:     packageFixedVersion,
		CalledVulns:      calledVulnList,
		UncalledVulns:    uncalledVulnList,
		VulnCount:        count,
	}

	if vulnPkg.Package.ImageOrigin != nil {
		packageLayerDetail := OutputPackageLayerDetail{
			LayerID:     vulnPkg.Package.ImageOrigin.LayerID,
			InBaseImage: vulnPkg.Package.ImageOrigin.InBaseImage,
		}
		packageLayerDetail.LayerCommand, packageLayerDetail.LayerCommandTooltip = formatLayerCommand(vulnPkg.Package.ImageOrigin.OriginCommand)
		packageResult.LayerDetail = packageLayerDetail
	}

	return packageResult
}

// processOutputVulnerabilityGroups processes vulnerability groups within a package.
// It populates the called and uncalled vulnerability maps and updates the vulnerability count
// based on the severity and call analysis information of each group.
func processOutputVulnerabilityGroups(vulnPkg models.PackageVulns) (map[string]OutputVulnResult, map[string]OutputVulnResult, OutputVulnCount) {
	calledVulnMap := make(map[string]OutputVulnResult)
	uncalledVulnMap := make(map[string]OutputVulnResult)
	var count OutputVulnCount

	for _, group := range vulnPkg.Groups {
		slices.SortFunc(group.IDs, identifiers.IDSortFunc)
		slices.SortFunc(group.Aliases, identifiers.IDSortFunc)

		representID := group.IDs[0]

		vuln := OutputVulnResult{
			ID:       representID,
			GroupIDs: group.IDs,
			Aliases:  group.Aliases,
		}

		vuln.SeverityScore = group.MaxSeverity
		vuln.SeverityRating, _ = severity.CalculateRating(vuln.SeverityScore)
		if vuln.SeverityRating == UnknownRating {
			vuln.SeverityScore = "N/A"
		}
		count.SeverityCount = increaseSeverityCount(count.SeverityCount, vuln.SeverityRating)

		if group.IsCalled() {
			calledVulnMap[representID] = vuln
			count.CallAnalysisCount.Called += 1
		} else {
			uncalledVulnMap[representID] = vuln
			count.CallAnalysisCount.Uncalled += 1
		}
	}

	return calledVulnMap, uncalledVulnMap, count
}

func updateVulnerabilityDetails(vulnPkg models.PackageVulns, vulnMap map[string]OutputVulnResult, count *OutputVulnCount) {
	for _, vuln := range vulnPkg.Vulnerabilities {
		fixedVersion := getNextFixVersion(vuln.Affected, vulnPkg.Package.Version, vulnPkg.Package.Name, models.Ecosystem(vulnPkg.Package.Ecosystem))
		if outputVuln, exist := vulnMap[vuln.ID]; exist {
			outputVuln.FixedVersion = fixedVersion
			vulnMap[vuln.ID] = outputVuln
			if fixedVersion == UnfixedDescription {
				count.FixableCount.UnFixed += 1
			} else {
				count.FixableCount.Fixed += 1
			}
		}
	}
}

func getVulnList(vulnMap map[string]OutputVulnResult) []OutputVulnResult {
	vulnList := make([]OutputVulnResult, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		vulnList = append(vulnList, vuln)
	}

	// Sort projectResults to ensure consistent output
	slices.SortFunc(vulnList, func(a, b OutputVulnResult) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return vulnList
}

// getNextFixVersion returns the lowest fixed version for a given package and
// its current installed version, considering the affected ranges. If no fix is
// available, it returns "No fix available".
func getNextFixVersion(allAffected []models.Affected, installedVersion string, installedPackage string, ecosystem models.Ecosystem) string {
	ecosystemPrefix := models.Ecosystem(strings.Split(string(ecosystem), ":")[0])
	vp, err := semantic.Parse(installedVersion, ecosystemPrefix)
	if err != nil {
		return VersionUnsupported
	}

	minFixVersion := UnfixedDescription
	for _, affected := range allAffected {
		if affected.Package.Name != installedPackage || affected.Package.Ecosystem != ecosystem {
			continue
		}
		for _, affectedRange := range affected.Ranges {
			for _, affectedEvent := range affectedRange.Events {
				// Skip if it's not a fix version event or the installed version is greater than the fix version.
				if affectedEvent.Fixed == "" || vp.CompareStr(affectedEvent.Fixed) > 0 {
					continue
				}

				// Find the minium fix version
				if minFixVersion == UnfixedDescription || semantic.MustParse(affectedEvent.Fixed, ecosystemPrefix).CompareStr(minFixVersion) < 0 {
					minFixVersion = affectedEvent.Fixed
				}
			}
		}
	}

	return minFixVersion
}

// getPackageFixedVersion determines the highest version that resolves the most known vulnerabilities for a package.
func getPackageFixedVersion(ecosystem string, allVulns []OutputVulnResult) string {
	ecosystemPrefix := models.Ecosystem(strings.Split(ecosystem, ":")[0])
	maxFixVersion := ""
	var vp semantic.Version
	for _, vuln := range allVulns {
		if vuln.FixedVersion == VersionUnsupported {
			return UnfixedDescription
		}

		// Skip vulnerabilities without a fixed version.
		if vuln.FixedVersion == UnfixedDescription {
			continue
		}

		if maxFixVersion == "" {
			maxFixVersion = vuln.FixedVersion
			vp = semantic.MustParse(maxFixVersion, ecosystemPrefix)

			continue
		}

		// Update if the current vulnerability's fixed version is higher
		if vp.CompareStr(vuln.FixedVersion) < 0 {
			maxFixVersion = vuln.FixedVersion
			vp = semantic.MustParse(maxFixVersion, ecosystemPrefix)
		}
	}

	// Default to UnfixedDescription if no fix version is found.
	if maxFixVersion == "" {
		maxFixVersion = UnfixedDescription
	}

	return maxFixVersion
}

func updateVulnCount(original OutputVulnCount, newAdded OutputVulnCount) OutputVulnCount {
	original.SeverityCount = addSeverityCount(original.SeverityCount, newAdded.SeverityCount)
	original.CallAnalysisCount = addCallAnalysisCount(original.CallAnalysisCount, newAdded.CallAnalysisCount)
	original.FixableCount = addFixableCount(original.FixableCount, newAdded.FixableCount)

	return original
}

func addSeverityCount(original OutputSeverityCount, newAdded OutputSeverityCount) OutputSeverityCount {
	original.Critical += newAdded.Critical
	original.High += newAdded.High
	original.Medium += newAdded.Medium
	original.Low += newAdded.Low
	original.Unknown += newAdded.Unknown

	return original
}

func addCallAnalysisCount(original OutputCallAnalysisCount, newAdded OutputCallAnalysisCount) OutputCallAnalysisCount {
	original.Called += newAdded.Called
	original.Uncalled += newAdded.Uncalled

	return original
}

func addFixableCount(original OutputFixableCount, newAdded OutputFixableCount) OutputFixableCount {
	original.Fixed += newAdded.Fixed
	original.UnFixed += newAdded.UnFixed

	return original
}

func increaseSeverityCount(severityCount OutputSeverityCount, typeName string) OutputSeverityCount {
	switch typeName {
	case "CRITICAL":
		severityCount.Critical += 1
	case "HIGH":
		severityCount.High += 1
	case "MEDIUM":
		severityCount.Medium += 1
	case "LOW":
		severityCount.Low += 1
	case "UNKNOWN":
		severityCount.Unknown += 1
	}

	return severityCount
}

func isOSEcosystem(ecosystem string) bool {
	for _, image := range baseImages {
		if strings.HasPrefix(ecosystem, image) {
			return true
		}
	}

	return false
}

func getAllLayerInfo(result []OutputEcosystemResult) []OutputLayerInfo {
	layerMap := make(map[string]string)
	layerCount := make(map[string]OutputVulnCount)
	layerIndex := 0

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			for _, packageInfo := range source.Packages {
				layerID := packageInfo.LayerDetail.LayerID
				layerCommand := packageInfo.LayerDetail.LayerCommand

				// Check if this layer ID and command combination is already in the map
				if _, ok := layerMap[layerID]; !ok {
					var resultCount OutputVulnCount
					resultCount = updateVulnCount(resultCount, packageInfo.VulnCount)
					layerCount[layerID] = resultCount
					layerMap[layerID] = layerCommand // Store the layer ID and command
					layerIndex++
				} else {
					resultCount := layerCount[layerID]
					resultCount = updateVulnCount(resultCount, packageInfo.VulnCount)
					layerCount[layerID] = resultCount
				}
			}
		}
	}

	// Convert the map to a slice of LayerInfo
	layers := make([]OutputLayerInfo, 0, len(layerMap))
	i := 0
	for layerID, layerCommand := range layerMap {
		if layerCommand == "" {
			continue
		}
		layers = append(layers, OutputLayerInfo{
			// TODO(gongh@): replace with the actual layer index
			Index:        i,
			LayerCommand: layerCommand,
			LayerID:      layerID,
			Count:        layerCount[layerID],
		})
		i++
	}

	return layers
}

func getOutputVulnTypeCount(result []OutputEcosystemResult) OutputVulnTypeCount {
	var vulnCount OutputVulnTypeCount

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			if ecosystem.IsOS {
				vulnCount.OS += source.PackageTypeCount.Called
			} else {
				vulnCount.Project += source.PackageTypeCount.Called
			}
			vulnCount.Uncalled += source.PackageTypeCount.Uncalled
		}
	}

	vulnCount.All = vulnCount.OS + vulnCount.Project

	return vulnCount
}
