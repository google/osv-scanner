package output

import (
	"cmp"
	"encoding/json"
	"io"
	"slices"
	"sort"
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
	VulnTypeSummary     VulnTypeSummary
	PackageTypeCount    AnalysisCount
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
	PackageTypeCount AnalysisCount
	Packages         []PackageResult
	VulnCount        VulnCount
}

// PackageResult represents the vulnerability scanning results for a package.
type PackageResult struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	RegularVulns     []VulnResult
	HiddenVulns      []VulnResult
	LayerDetail      PackageLayerDetail
	VulnCount        VulnCount
}

// VulnResult represents a single vulnerability.
type VulnResult struct {
	ID               string
	GroupIDs         []string
	Aliases          []string
	IsFixable        bool
	FixedVersion     string
	VulnAnalysisType VulnAnalysisType
	SeverityRating   severity.Rating
	SeverityScore    string
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

// VulnSummary represents the count of each vulnerability type at the top level
// of the scanning results.
type VulnTypeSummary struct {
	All     int
	OS      int
	Project int
	Hidden  int
}

// VulnCount represents the counts of vulnerabilities by call analysis, severity and fixed/unfixed status
type VulnCount struct {
	AnalysisCount AnalysisCount
	// Only regular vulnerabilities are included in the severity and fixable counts.
	SeverityCount SeverityCount
	FixableCount  FixableCount
}

// SeverityCount represents the counts of vulnerabilities by severity level.
type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// AnalysisCount represents the counts of vulnerabilities by analysis type (e.g. call analysis)
type AnalysisCount struct {
	Regular int
	Hidden  int
}

// FixableCount represents the counts of vulnerabilities by fixable status.
type FixableCount struct {
	Fixed   int
	UnFixed int
}

type VulnAnalysisType int

const (
	VulnTypeRegular     VulnAnalysisType = iota // 0
	VulnTypeUncalled                            // 1
	VulnTypeUnimportant                         // 2
)

const UnfixedDescription = "No fix available"
const VersionUnsupported = "N/A"

// osEcosystems is a list of OS images.
var osEcosystems = []string{"Debian", "Alpine", "Ubuntu"}

// PrintResults prints the output to the outputWriter.
// This function is for testing purposes only, to visualize the result format.
func PrintResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	result := BuildResults(vulnResult)
	//nolint:musttag
	return encoder.Encode(result)
}

// BuildResults constructs the output result structure from the vulnerability results.
//
// This function creates a hierarchical representation of the results, starting from the overall
// summary and drilling down to ecosystems, sources, packages, and vulnerability details.
// This structured format facilitates generating various output formats (e.g., table, HTML, etc.).
func BuildResults(vulnResult *models.VulnerabilityResults) Result {
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
		sourceResult := processSource(packageSource)
		ecosystemMap[sourceResult.Ecosystem] = append(ecosystemMap[sourceResult.Ecosystem], sourceResult)
		resultCount.Add(sourceResult.VulnCount)
	}

	// Build the final result
	return buildResult(ecosystemMap, resultCount)
}

// buildResult builds the final Result object from the ecosystem map and total vulnerability count.
func buildResult(ecosystemMap map[string][]SourceResult, resultCount VulnCount) Result {
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
	vulnTypeSummary := getVulnTypeSummary(ecosystemResults)
	packageTypeCount := getPackageTypeCount(ecosystemResults)

	return Result{
		Ecosystems:          ecosystemResults,
		VulnTypeSummary:     vulnTypeSummary,
		PackageTypeCount:    packageTypeCount,
		VulnCount:           resultCount,
		IsContainerScanning: isContainerScanning,
		AllLayers:           layers,
	}
}

// processSource processes a single source (lockfile or artifact) and returns an SourceResult.
func processSource(packageSource models.PackageSource) SourceResult {
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
		packageResult := processPackage(vulnPkg)
		packages = append(packages, packageResult)
		packageSet[key] = struct{}{}

		sourceResult.VulnCount.Add(packageResult.VulnCount)
		if len(packageResult.RegularVulns) != 0 {
			sourceResult.PackageTypeCount.Regular += 1
		}
		// A package can be counted as both regular and hidden if it has both called and uncalled vulnerabilities.
		if len(packageResult.HiddenVulns) != 0 {
			sourceResult.PackageTypeCount.Hidden += 1
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

// processPackage processes vulnerability information for a given package
// and generates a structured output result.
//
// This function processes the vulnerability groups, updates vulnerability details,
// and constructs the final output result for the package, including details about
// called and uncalled vulnerabilities, fixable counts, and layer information (if available).
func processPackage(vulnPkg models.PackageVulns) PackageResult {
	regularVulnMap, hiddenVulnMap := processVulnGroups(vulnPkg)
	updateVuln(regularVulnMap, vulnPkg)
	updateVuln(hiddenVulnMap, vulnPkg)

	regularVulnList := getVulnList(regularVulnMap)
	hiddenVulnList := getVulnList(hiddenVulnMap)

	count := calculateCount(regularVulnList, hiddenVulnList)

	packageFixedVersion := calculatePackageFixedVersion(vulnPkg.Package.Ecosystem, regularVulnList)

	packageResult := PackageResult{
		Name:             vulnPkg.Package.Name,
		InstalledVersion: vulnPkg.Package.Version,
		FixedVersion:     packageFixedVersion,
		RegularVulns:     regularVulnList,
		HiddenVulns:      hiddenVulnList,
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

// processVulnGroups processes vulnerability groups within a package.
//
// Returns:
//
//	regularVulnMap: A map of regular vulnerabilities, keyed by their representative ID.
//	hiddenVulnMap: A map of unimportant vulnerabilities, keyed by their representative ID.
func processVulnGroups(vulnPkg models.PackageVulns) (map[string]VulnResult, map[string]VulnResult) {
	regularVulnMap := make(map[string]VulnResult)
	hiddenVulnMap := make(map[string]VulnResult)

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

		if group.IsCalled() && !group.IsGroupUnimportant() {
			vuln.VulnAnalysisType = VulnTypeRegular
			regularVulnMap[representID] = vuln
		} else if group.IsGroupUnimportant() {
			vuln.VulnAnalysisType = VulnTypeUnimportant
			hiddenVulnMap[representID] = vuln
		} else if !group.IsCalled() {
			vuln.VulnAnalysisType = VulnTypeUncalled
			hiddenVulnMap[representID] = vuln
		}
	}

	return regularVulnMap, hiddenVulnMap
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
	v.AnalysisCount.Add(other.AnalysisCount)
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
func (c *AnalysisCount) Add(other AnalysisCount) {
	c.Regular += other.Regular
	c.Hidden += other.Hidden
}

// Add adds the counts from another FixableCount to the receiver.
func (c *FixableCount) Add(other FixableCount) {
	c.Fixed += other.Fixed
	c.UnFixed += other.UnFixed
}

func (vt VulnAnalysisType) String() string {
	switch vt {
	case VulnTypeRegular:
		return "Regular"
	case VulnTypeUncalled:
		return "Uncalled"
	case VulnTypeUnimportant:
		return "Unimportant"
	default:
		return "Unknown"
	}
}

func getFilteredVulnReasons(vulns []VulnResult) []string {
	reasonMap := make(map[string]bool)
	for _, vuln := range vulns {
		if vuln.VulnAnalysisType != VulnTypeRegular {
			reasonMap[vuln.VulnAnalysisType.String()] = true
		}
	}

	reasons := make([]string, 0, len(reasonMap))
	for reason := range reasonMap {
		reasons = append(reasons, reason)
	}

	sort.Strings(reasons)

	return reasons
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
	for _, image := range osEcosystems {
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

func getVulnTypeSummary(result []EcosystemResult) VulnTypeSummary {
	var vulnTypeSummary VulnTypeSummary

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			if ecosystem.IsOS {
				vulnTypeSummary.OS += source.VulnCount.AnalysisCount.Regular
			} else {
				vulnTypeSummary.Project += source.VulnCount.AnalysisCount.Regular
			}
			vulnTypeSummary.Hidden += source.VulnCount.AnalysisCount.Hidden
		}
	}

	vulnTypeSummary.All = vulnTypeSummary.OS + vulnTypeSummary.Project

	return vulnTypeSummary
}

func getPackageTypeCount(result []EcosystemResult) AnalysisCount {
	var packageCount AnalysisCount

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			packageCount.Regular += source.PackageTypeCount.Regular
			packageCount.Hidden += source.PackageTypeCount.Hidden
		}
	}

	return packageCount
}

// calculateCount calculates the vulnerability counts based on the provided
// lists of regular and hidden vulnerabilities.
func calculateCount(regularVulnList, hiddenVulnList []VulnResult) VulnCount {
	var count VulnCount

	for _, vuln := range regularVulnList {
		if vuln.IsFixable {
			count.FixableCount.Fixed += 1
		} else {
			count.FixableCount.UnFixed += 1
		}

		count.SeverityCount = increaseSeverityCount(count.SeverityCount, vuln.SeverityRating)
	}
	count.AnalysisCount.Regular = len(regularVulnList)
	count.AnalysisCount.Hidden = len(hiddenVulnList)

	return count
}
