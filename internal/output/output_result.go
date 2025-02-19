package output

import (
	"cmp"
	"encoding/json"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/identifiers"
	"github.com/google/osv-scanner/v2/internal/semantic"
	"github.com/google/osv-scanner/v2/internal/utility/results"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// Result represents the vulnerability scanning results for output report.
type Result struct {
	Ecosystems []EcosystemResult
	// Container scanning related
	IsContainerScanning bool
	ImageInfo           ImageInfo
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
	Name string
	// OSPackageNames represents the actual installed binary names. This is primarily used for container scanning.
	OSPackageNames   []string
	InstalledVersion string
	Commit           string
	FixedVersion     string
	// RegularVulns holds all the vulnerabilities that should be displayed to users
	RegularVulns []VulnResult
	// HiddenVulns holds all the vulnerabilities that should not be displayed to users, such as those deemed unimportant or uncalled.
	HiddenVulns []VulnResult
	LayerDetail PackageContainerInfo
	VulnCount   VulnCount
}

// VulnResult represents a single vulnerability.
type VulnResult struct {
	ID       string
	GroupIDs []string
	Aliases  []string
	// Description is either the Vulnerability.Summary (default) or the Vulnerability.Details.
	Description      string
	IsFixable        bool
	FixedVersion     string
	VulnAnalysisType VulnAnalysisType
	SeverityRating   severity.Rating
	SeverityScore    string
}

type ImageInfo struct {
	OS            string
	AllLayers     []LayerInfo
	AllBaseImages []BaseImageGroupInfo
}

// PackageContainerInfo represents detailed layer tracing information about a package.
type PackageContainerInfo struct {
	LayerIndex    int
	LayerInfo     LayerInfo
	BaseImageInfo BaseImageGroupInfo
}

type BaseImageGroupInfo struct {
	Index         int
	BaseImageInfo []models.BaseImageDetails
	AllLayers     []LayerInfo
	Count         VulnCount
}

type LayerInfo struct {
	Index         int
	LayerMetadata models.LayerMetadata
	Count         VulnCount
}

// VulnTypeSummary represents the count of each vulnerability type at the top level
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

RowLoop:
	for _, packageSource := range vulnResult.Results {
		for _, annotation := range packageSource.ExperimentalAnnotations {
			if annotation == extractor.InsideOSPackage {
				continue RowLoop
			}
		}

		// Process vulnerabilities for each source
		sourceResults := processSource(packageSource)
		for ecosystem, source := range sourceResults {
			ecosystemMap[ecosystem] = append(ecosystemMap[ecosystem], source)
			resultCount.Add(source.VulnCount)
		}
	}

	return buildResult(ecosystemMap, resultCount, vulnResult.ImageMetadata)
}

// buildResult builds the final Result object from the ecosystem map and total vulnerability count.
func buildResult(ecosystemMap map[string][]SourceResult, resultCount VulnCount, imageMetadata *models.ImageMetadata) Result {
	result := Result{}
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

	vulnTypeSummary := getVulnTypeSummary(ecosystemResults)
	packageTypeCount := getPackageTypeCount(ecosystemResults)

	result.Ecosystems = ecosystemResults
	result.VulnTypeSummary = vulnTypeSummary
	result.PackageTypeCount = packageTypeCount
	result.VulnCount = resultCount

	if imageMetadata != nil {
		populateResultWithImageMetadata(&result, *imageMetadata)
	}

	return result
}

// populateResultWithImageMetadata modifies the result by adding image metadata to it.
// It uses a pointer receiver (*Result) to modify the original result in place.
func populateResultWithImageMetadata(result *Result, imageMetadata models.ImageMetadata) {
	allLayers := buildLayers(imageMetadata.LayerMetadata)
	allBaseImages := buildBaseImages(imageMetadata.BaseImages)

	layerCount := make([]VulnCount, len(allLayers))
	baseImageCount := make([]VulnCount, len(allBaseImages))

	// Calculate total vulns for each layer and base image.
	for _, ecosystem := range result.Ecosystems {
		for _, source := range ecosystem.Sources {
			for _, pkg := range source.Packages {
				layerIndex := pkg.LayerDetail.LayerIndex
				layerCount[layerIndex].Add(pkg.VulnCount)

				baseImageIndex := allLayers[layerIndex].LayerMetadata.BaseImageIndex
				baseImageCount[baseImageIndex].Add(pkg.VulnCount)
			}
		}
	}

	baseImageMap := make(map[int][]LayerInfo)

	// Update vuln count for layers and base images
	for i := range allLayers {
		allLayers[i].Count = layerCount[i]
		baseImageIndex := allLayers[i].LayerMetadata.BaseImageIndex
		baseImageMap[baseImageIndex] = append(baseImageMap[baseImageIndex], allLayers[i])
	}

	for i := range allBaseImages {
		allBaseImages[i].Count = baseImageCount[i]
		slices.SortFunc(baseImageMap[i], func(a, b LayerInfo) int {
			return cmp.Compare(a.Index, b.Index)
		})
		allBaseImages[i].AllLayers = baseImageMap[i]
	}

	// Fill up Layer info for each package
	for i := range result.Ecosystems {
		for j := range result.Ecosystems[i].Sources {
			for k := range result.Ecosystems[i].Sources[j].Packages {
				// Pointer to packageInfo to modify directly.
				packageInfo := &result.Ecosystems[i].Sources[j].Packages[k]

				layerIndex := packageInfo.LayerDetail.LayerIndex
				packageInfo.LayerDetail.LayerInfo = allLayers[layerIndex]

				baseImageIndex := allLayers[layerIndex].LayerMetadata.BaseImageIndex
				packageInfo.LayerDetail.BaseImageInfo = allBaseImages[baseImageIndex]
			}
		}
	}

	// Display base images in a reverse order
	slices.SortFunc(allBaseImages, func(a, b BaseImageGroupInfo) int {
		return cmp.Compare(b.Index, a.Index)
	})

	result.ImageInfo = ImageInfo{
		OS:            imageMetadata.OS,
		AllLayers:     allLayers,
		AllBaseImages: allBaseImages,
	}

	if len(allLayers) != 0 {
		result.IsContainerScanning = true
	}
}

func buildBaseImages(baseImages [][]models.BaseImageDetails) []BaseImageGroupInfo {
	allBaseImages := make([]BaseImageGroupInfo, len(baseImages))
	for i, baseImage := range baseImages {
		allBaseImages[i] = BaseImageGroupInfo{
			Index:         i,
			BaseImageInfo: baseImage,
		}
	}

	return allBaseImages
}

func buildLayers(layerMetadata []models.LayerMetadata) []LayerInfo {
	allLayers := make([]LayerInfo, len(layerMetadata))
	for i, layer := range layerMetadata {
		allLayers[i] = LayerInfo{
			Index:         i,
			LayerMetadata: layer,
		}
	}

	return allLayers
}

// processSource processes a single source (lockfile or artifact) and returns a map of ecosystems to their corresponding SourceResults.
func processSource(packageSource models.PackageSource) map[string]SourceResult {
	// Handle potential duplicate source packages with different OS package names.
	// This map ensures each package is processed only once,
	// with subsequent occurrences only adding their OSPackageName to the list.
	packageMap := make(map[string]PackageResult)
	// Use a map to handle one source contains packages form multiple ecosystems
	sourceResults := make(map[string]SourceResult)

	// If no packages with issues are found, mark the ecosystem as empty.
	if len(packageSource.Packages) == 0 {
		sourceResults[""] = SourceResult{
			Name:      packageSource.Source.String(),
			Ecosystem: "",
			Packages:  []PackageResult{},
		}

		return sourceResults
	}

	for _, vulnPkg := range packageSource.Packages {
		if _, exists := sourceResults[vulnPkg.Package.Ecosystem]; !exists {
			sourceResults[vulnPkg.Package.Ecosystem] = SourceResult{
				Name:      packageSource.Source.String(),
				Ecosystem: vulnPkg.Package.Ecosystem,
			}
		}

		// Use a unique identifier (package name + version) to deduplicate packages (same version),
		// ensuring each is processed only once.
		key := vulnPkg.Package.Ecosystem + ":" + vulnPkg.Package.Name + ":" + vulnPkg.Package.Version
		if _, exist := packageMap[key]; exist {
			pkgTemp := packageMap[key]
			pkgTemp.OSPackageNames = append(pkgTemp.OSPackageNames, vulnPkg.Package.OSPackageName)
			packageMap[key] = pkgTemp

			continue // Skip processing this vulnPkg as it was already added
		}

		packageResult := processPackage(vulnPkg)
		if vulnPkg.Package.ImageOrigin != nil {
			packageResult.LayerDetail = PackageContainerInfo{
				LayerIndex: vulnPkg.Package.ImageOrigin.Index,
			}
		}
		packageMap[key] = packageResult
	}

	for ecosystem, sourceResult := range sourceResults {
		var packages []PackageResult
		for key, pkg := range packageMap {
			if !strings.HasPrefix(key, ecosystem) {
				continue
			}

			packages = append(packages, pkg)

			sourceResult.VulnCount.Add(pkg.VulnCount)
			if len(pkg.RegularVulns) != 0 {
				sourceResult.PackageTypeCount.Regular += 1
			}
			// A package can be counted as both regular and hidden if it has both called and uncalled vulnerabilities.
			if len(pkg.HiddenVulns) != 0 {
				sourceResult.PackageTypeCount.Hidden += 1
			}
		}

		// Sort packageResults to ensure consistent output
		slices.SortFunc(packages, func(a, b PackageResult) int {
			return cmp.Or(
				cmp.Compare(a.Name, b.Name),
				cmp.Compare(a.InstalledVersion, b.InstalledVersion),
				cmp.Compare(a.Commit, b.Commit),
			)
		})
		sourceResult.Packages = packages
		sourceResults[ecosystem] = sourceResult
	}

	return sourceResults
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
		OSPackageNames:   []string{vulnPkg.Package.OSPackageName},
		InstalledVersion: vulnPkg.Package.Version,
		Commit:           vulnPkg.Package.Commit,
		FixedVersion:     packageFixedVersion,
		RegularVulns:     regularVulnList,
		HiddenVulns:      hiddenVulnList,
		VulnCount:        count,
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
		aliases := group.Aliases
		if len(group.Aliases) > 0 && group.Aliases[0] == representID {
			aliases = aliases[1:]
		}

		vuln := VulnResult{
			ID:       representID,
			GroupIDs: group.IDs,
			Aliases:  aliases,
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
			outputVuln.Description = vuln.Summary
			if outputVuln.Description == "" {
				outputVuln.Description = vuln.Details
			}
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
		return identifiers.IDSortFunc(a.ID, b.ID)
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

func getFilteredVulnReasons(vulns []VulnResult) string {
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

	return strings.Join(reasons, ", ")
}

func getBaseImageName(baseImageInfo BaseImageGroupInfo) string {
	if len(baseImageInfo.BaseImageInfo) > 0 {
		return baseImageInfo.BaseImageInfo[0].Name
	}

	return ""
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

// formatLayerCommand formats the layer command output for better readability.
// It replaces the unreadable file ID with "UNKNOWN" and extracting the ID separately.
func formatLayerCommand(command string) []string {
	command = cleanupSpaces(command)
	re := cachedregexp.MustCompile(`(dir|file):([a-f0-9]+)`)
	match := re.FindStringSubmatch(command)

	if len(match) > 2 {
		prefix := match[1] // Capture "dir" or "file"
		hash := match[2]   // Capture the hash ID
		newCommand := re.ReplaceAllString(command, prefix+":UNKNOWN")

		return []string{newCommand, "File ID: " + hash}
	}

	return []string{command, ""}
}

// cleanupSpaces uses a regular expression to replace multiple spaces with a single space.
func cleanupSpaces(s string) string {
	re := cachedregexp.MustCompile(`\s+`)
	s = re.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)

	return s
}

func getInstalledVersionOrCommit(pkg PackageResult) string {
	result := pkg.InstalledVersion
	if result == "" && pkg.Commit != "" {
		result = results.GetShortCommit(pkg.Commit)
	}

	return result
}
