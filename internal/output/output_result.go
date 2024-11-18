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

// Result represents the vulnerability scanning results for output report.
type Result struct {
	Ecosystems []EcosystemResult
	// Container scanning related
	IsContainerScanning bool
	AllLayers           []LayerInfo
	VulnTypeCount       VulnTypeCount
	VulnCount           VulnCount
}

// EcosystemResult represents the vulnerability scanning results for an ecosystem.
type EcosystemResult struct {
	Name    string
	Sources []SourceResult
	IsOS    bool
}

// SourceResult represents the vulnerability scanning results for a source file.
type SourceResult struct {
	Name             string
	Ecosystem        string
	PackageTypeCount CallAnalysisCount
	Packages         []PackageResult
	VulnCount        VulnCount
}

// PackageResult represents the vulnerability scanning results for a package.
type PackageResult struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	CalledVulns      []VulnResult
	UncalledVulns    []VulnResult
	LayerDetail      PackageLayerDetail
	VulnCount        VulnCount
}

// VulnResult represents a single vulnerability.
type VulnResult struct {
	ID             string
	GroupIDs       []string
	Aliases        []string
	IsFixable      bool
	FixedVersion   string
	SeverityRating severity.Rating
	SeverityScore  string
}

// PackageLayerDetail represents detailed layer tracing information about a package.
type PackageLayerDetail struct {
	LayerCommand         string
	LayerCommandDetailed string
	LayerID              string
	InBaseImage          bool
}

type LayerInfo struct {
	Index        int
	LayerCommand string
	LayerID      string
	Count        VulnCount
}

// VulnCount represents the counts of vulnerabilities by severity and fixed/unfixed status
type VulnCount struct {
	CallAnalysisCount CallAnalysisCount
	// Only called vulnerabilities are included in the severity and fixable counts.
	SeverityCount SeverityCount
	FixableCount  FixableCount
}

type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

type VulnTypeCount struct {
	All      int
	OS       int
	Project  int
	Uncalled int
}

type CallAnalysisCount struct {
	Called   int
	Uncalled int
}

type FixableCount struct {
	Fixed   int
	UnFixed int
}

const UnfixedDescription = "No fix available"
const VersionUnsupported = "N/A"

// baseImages is a list of OS images.
var baseImages = []string{"Debian", "Alpine", "Ubuntu"}

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
func BuildOutputResults(vulnResult *models.VulnerabilityResults) Result {
	var ecosystemMap = make(map[string][]SourceResult)
	var resultCount VulnCount

	for _, packageSource := range vulnResult.Results {
		// Temporary workaround: it is a heuristic to ignore installed packages
		// which are already covered by OS-specific vulnerabilities.
		// This filtering should be handled by the container scanning process.
		// TODO(gongh@): Revisit this once container scanning can distinguish these cases.
		if strings.Contains(packageSource.Source.String(), "/usr/lib/") {
			continue
		}

		// Process vulnerabilities for each source
		sourceResult := processOutputSource(packageSource)
		ecosystemMap[sourceResult.Ecosystem] = append(ecosystemMap[sourceResult.Ecosystem], sourceResult)
		resultCount.Add(sourceResult.VulnCount)
	}

	// Build the final result
	return buildOutputResult(ecosystemMap, resultCount)
}

// buildOutputResult builds the final OutputResult object from the ecosystem map and total vulnerability count.
func buildOutputResult(ecosystemMap map[string][]SourceResult, resultCount VulnCount) Result {
	var ecosystemResults []EcosystemResult
	var osResults []EcosystemResult
	for ecosystem, sources := range ecosystemMap {
		ecosystemResult := EcosystemResult{
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
	slices.SortFunc(ecosystemResults, func(a, b EcosystemResult) int {
		return cmp.Compare(a.Name, b.Name)
	})

	// Sort osResults to ensure consistent output
	slices.SortFunc(osResults, func(a, b EcosystemResult) int {
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

	return Result{
		Ecosystems:          ecosystemResults,
		VulnTypeCount:       vulnTypeCount,
		VulnCount:           resultCount,
		IsContainerScanning: isContainerScanning,
		AllLayers:           layers,
	}
}

// processOutputSource processes a single source (lockfile or artifact) and returns an SourceResult.
func processOutputSource(packageSource models.PackageSource) SourceResult {
	var sourceResult SourceResult
	packages := make([]PackageResult, 0)
	packageSet := make(map[string]struct{})

	for _, vulnPkg := range packageSource.Packages {
		sourceResult.Ecosystem = vulnPkg.Package.Ecosystem
		key := vulnPkg.Package.Name + ":" + vulnPkg.Package.Version
		if _, exist := packageSet[key]; exist {
			// In container scanning, the same package (same name and version) might be found multiple times
			// within a single source. This happens because we use the upstream source name instead of
			// the Linux distribution package name.
			continue
		}
		packageResult := processOutputPackage(vulnPkg)
		packages = append(packages, packageResult)
		packageSet[key] = struct{}{}

		sourceResult.VulnCount.Add(packageResult.VulnCount)
		if len(packageResult.CalledVulns) != 0 {
			sourceResult.PackageTypeCount.Called += 1
		}
		// A package can be counted as both called and uncalled if it has both called and uncalled vulnerabilities.
		if len(packageResult.UncalledVulns) != 0 {
			sourceResult.PackageTypeCount.Uncalled += 1
		}
	}
	// Sort packageResults to ensure consistent output
	slices.SortFunc(packages, func(a, b PackageResult) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.InstalledVersion, b.InstalledVersion),
		)
	})
	sourceResult.Name = packageSource.Source.String()
	sourceResult.Packages = packages

	return sourceResult
}

// processOutputPackage processes vulnerability information for a given package
// and generates a structured output result.
//
// This function processes the vulnerability groups, updates vulnerability details,
// and constructs the final output result for the package, including details about
// called and uncalled vulnerabilities, fixable counts, and layer information (if available).
func processOutputPackage(vulnPkg models.PackageVulns) PackageResult {
	calledVulnMap, uncalledVulnMap := processOutputVulnGroups(vulnPkg)
	updateVuln(calledVulnMap, vulnPkg)
	updateVuln(uncalledVulnMap, vulnPkg)

	calledVulnList := getVulnList(calledVulnMap)
	uncalledVulnList := getVulnList(uncalledVulnMap)

	count := calculateCount(calledVulnList, uncalledVulnList)

	packageFixedVersion := calculatePackageFixedVersion(vulnPkg.Package.Ecosystem, calledVulnList)

	packageResult := PackageResult{
		Name:             vulnPkg.Package.Name,
		InstalledVersion: vulnPkg.Package.Version,
		FixedVersion:     packageFixedVersion,
		CalledVulns:      calledVulnList,
		UncalledVulns:    uncalledVulnList,
		VulnCount:        count,
	}

	if vulnPkg.Package.ImageOrigin != nil {
		packageLayerDetail := PackageLayerDetail{
			LayerID:     vulnPkg.Package.ImageOrigin.LayerID,
			InBaseImage: vulnPkg.Package.ImageOrigin.InBaseImage,
		}
		packageLayerDetail.LayerCommand, packageLayerDetail.LayerCommandDetailed = formatLayerCommand(vulnPkg.Package.ImageOrigin.OriginCommand)
		packageResult.LayerDetail = packageLayerDetail
	}

	return packageResult
}

// processOutputVulnGroups processes vulnerability groups within a package.
//
// Returns:
//
//	calledVulnMap: A map of called vulnerabilities, keyed by their representative ID.
//	uncalledVulnMap: A map of uncalled vulnerabilities, keyed by their representative ID.
func processOutputVulnGroups(vulnPkg models.PackageVulns) (map[string]VulnResult, map[string]VulnResult) {
	calledVulnMap := make(map[string]VulnResult)
	uncalledVulnMap := make(map[string]VulnResult)

	for _, group := range vulnPkg.Groups {
		slices.SortFunc(group.IDs, identifiers.IDSortFunc)
		slices.SortFunc(group.Aliases, identifiers.IDSortFunc)

		representID := group.IDs[0]

		vuln := VulnResult{
			ID:       representID,
			GroupIDs: group.IDs,
			Aliases:  group.Aliases,
		}

		vuln.SeverityScore = group.MaxSeverity
		vuln.SeverityRating, _ = severity.CalculateRating(vuln.SeverityScore)
		if vuln.SeverityRating == severity.UnknownRating {
			vuln.SeverityScore = "N/A"
		}

		if group.IsCalled() {
			calledVulnMap[representID] = vuln
		} else {
			uncalledVulnMap[representID] = vuln
		}
	}

	return calledVulnMap, uncalledVulnMap
}

// updateVuln updates each vulnerability info in vulnMap from the details of vulnPkg.Vulnerabilities.
func updateVuln(vulnMap map[string]VulnResult, vulnPkg models.PackageVulns) {
	for _, vuln := range vulnPkg.Vulnerabilities {
		fixable, fixedVersion := getNextFixVersion(vuln.Affected, vulnPkg.Package.Version, vulnPkg.Package.Name, models.Ecosystem(vulnPkg.Package.Ecosystem))
		if outputVuln, exist := vulnMap[vuln.ID]; exist {
			outputVuln.FixedVersion = fixedVersion
			outputVuln.IsFixable = fixable
			vulnMap[vuln.ID] = outputVuln
		}
	}
}

func getVulnList(vulnMap map[string]VulnResult) []VulnResult {
	vulnList := make([]VulnResult, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		vulnList = append(vulnList, vuln)
	}

	// Sort projectResults to ensure consistent output
	slices.SortFunc(vulnList, func(a, b VulnResult) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return vulnList
}

// getNextFixVersion finds the next fixed version for a given vulnerability.
// returns a boolean value indicating whether a fixed version is available.
func getNextFixVersion(allAffected []models.Affected, installedVersion string, installedPackage string, ecosystem models.Ecosystem) (bool, string) {
	ecosystemPrefix := models.Ecosystem(strings.Split(string(ecosystem), ":")[0])
	vp, err := semantic.Parse(installedVersion, ecosystemPrefix)
	if err != nil {
		return false, VersionUnsupported
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

				// Find the minimum fix version
				if minFixVersion == UnfixedDescription || semantic.MustParse(affectedEvent.Fixed, ecosystemPrefix).CompareStr(minFixVersion) < 0 {
					minFixVersion = affectedEvent.Fixed
				}
			}
		}
	}

	hasFixedVersion := minFixVersion != UnfixedDescription // Check if a fix is found

	return hasFixedVersion, minFixVersion
}

// calculatePackageFixedVersion determines the highest version that resolves the most known vulnerabilities for a package.
func calculatePackageFixedVersion(ecosystem string, allVulns []VulnResult) string {
	ecosystemPrefix := models.Ecosystem(strings.Split(ecosystem, ":")[0])
	maxFixVersion := ""
	var vp semantic.Version
	for _, vuln := range allVulns {
		// Skip vulnerabilities without a fixed version.
		if !vuln.IsFixable {
			continue
		}

		if maxFixVersion == "" {
			maxFixVersion = vuln.FixedVersion
			// maxFixVersion will always be valid as it comes from a parsable vulnerability fixed version.
			// If the fixed version was invalid, 'IsFixable' will be marked as false and will be skipped.
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

// Add adds the counts from another VulnCount to the receiver.
func (v *VulnCount) Add(other VulnCount) {
	v.SeverityCount.Add(other.SeverityCount)
	v.CallAnalysisCount.Add(other.CallAnalysisCount)
	v.FixableCount.Add(other.FixableCount)
}

// Add adds the counts from another SeverityCount to the receiver.
func (c *SeverityCount) Add(other SeverityCount) {
	c.Critical += other.Critical
	c.High += other.High
	c.Medium += other.Medium
	c.Low += other.Low
	c.Unknown += other.Unknown
}

// Add adds the counts from another CallAnalysisCount to the receiver.
func (c *CallAnalysisCount) Add(other CallAnalysisCount) {
	c.Called += other.Called
	c.Uncalled += other.Uncalled
}

// Add adds the counts from another FixableCount to the receiver.
func (c *FixableCount) Add(other FixableCount) {
	c.Fixed += other.Fixed
	c.UnFixed += other.UnFixed
}

func increaseSeverityCount(severityCount SeverityCount, severityType severity.Rating) SeverityCount {
	switch severityType {
	case severity.CriticalRating:
		severityCount.Critical += 1
	case severity.HighRating:
		severityCount.High += 1
	case severity.MediumRating:
		severityCount.Medium += 1
	case severity.LowRating:
		severityCount.Low += 1
	case severity.UnknownRating:
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

func getAllLayerInfo(result []EcosystemResult) []LayerInfo {
	layerMap := make(map[string]string)
	layerCount := make(map[string]VulnCount)

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			for _, packageInfo := range source.Packages {
				layerID := packageInfo.LayerDetail.LayerID
				layerCommand := packageInfo.LayerDetail.LayerCommand

				resultCount := layerCount[layerID] // Access the count, returns empty VulnCount if not found
				resultCount.Add(packageInfo.VulnCount)
				layerCount[layerID] = resultCount
				layerMap[layerID] = layerCommand // Store the layer ID and command
			}
		}
	}

	// Convert the map to a slice of LayerInfo
	layers := make([]LayerInfo, 0, len(layerMap))
	i := 0
	for layerID, layerCommand := range layerMap {
		if layerCommand == "" {
			continue
		}
		layers = append(layers, LayerInfo{
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

func getOutputVulnTypeCount(result []EcosystemResult) VulnTypeCount {
	var vulnCount VulnTypeCount

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

// calculateCount calculates the vulnerability counts based on the provided
// lists of called and uncalled vulnerabilities.
func calculateCount(calledVulnList, uncalledVulnList []VulnResult) VulnCount {
	var count VulnCount

	for _, vuln := range calledVulnList {
		if vuln.IsFixable {
			count.FixableCount.Fixed += 1
		} else {
			count.FixableCount.UnFixed += 1
		}

		count.SeverityCount = increaseSeverityCount(count.SeverityCount, vuln.SeverityRating)
	}
	count.CallAnalysisCount.Called = len(calledVulnList)
	count.CallAnalysisCount.Uncalled = len(uncalledVulnList)

	return count
}
