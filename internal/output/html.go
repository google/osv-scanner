package output

import (
	"cmp"
	"embed"
	"html/template"
	"io"
	"slices"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/identifiers"
	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/internal/utility/severity"
	"github.com/google/osv-scanner/pkg/models"
)

// HTMLResult represents the vulnerability scanning results for HTML report.
type HTMLResult struct {
	EcosystemResults    []HTMLEcosystemResult
	IsContainerScanning bool
	AllLayers           []HTMLLayerInfo
	HTMLVulnTypeCount   HTMLVulnTypeCount
	HTMLVulnCount       HTMLVulnCount
}

// HTMLEcosystemResult represents the vulnerability scanning results for an ecosystem.
type HTMLEcosystemResult struct {
	Ecosystem string
	Sources   []HTMLSourceResult
	IsOS      bool
}

// HTMLSourceResult represents the vulnerability scanning results for a source file.
type HTMLSourceResult struct {
	Source               string
	Ecosystem            string
	PackageResults       []HTMLPackageResult
	CalledPackageCount   int
	UncalledPackageCount int
	HTMLVulnCount        HTMLVulnCount
}

// HTMLPackageResult represents the vulnerability scanning results for a package.
type HTMLPackageResult struct {
	Name                   string
	Ecosystem              string
	Source                 string
	CalledVulns            []HTMLVulnResult
	UncalledVulns          []HTMLVulnResult
	InstalledVersion       string
	FixedVersion           string
	HTMLVulnCount          HTMLVulnCount
	HTMLPackageLayerDetail HTMLPackageLayerDetail
}

// HTMLVulnResult represents a single vulnerability.
type HTMLVulnResult struct {
	Summary HTMLVulnResultSummary
	Detail  HTMLVulnResultDetail
}

// HTMLVulnResultSummary represents summary information about a vulnerability.
type HTMLVulnResultSummary struct {
	ID               string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	SeverityRating   string
	SeverityScore    string
}

// HTMLPackageLayerDetail represents detailed layer tracing information about a package.
type HTMLPackageLayerDetail struct {
	LayerCommand        string
	LayerCommandTooltip string
	LayerID             string
	InBaseImage         bool
}

// HTMLVulnResultDetail represents detailed information about a vulnerability.
type HTMLVulnResultDetail struct {
	GroupIDs            []string
	CVE                 string
	Aliases             []string
	LayerCommand        string
	LayerCommandTooltip string
	LayerID             string
	InBaseImage         bool
}

type HTMLLayerInfo struct {
	Index        int
	LayerCommand string
	LayerID      string
	Count        HTMLVulnCount
}

// HTMLVulnCount represents the counts of vulnerabilities by severity and fixed/unfixed status
type HTMLVulnCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	Called   int
	Uncalled int
	Fixed    int
	UnFixed  int
}

type HTMLVulnTypeCount struct {
	All      int
	OS       int
	Project  int
	Uncalled int
}

const UnknownRating = "UNKNOWN"

// HTML templates directory
const TemplateDir = "html/*"

//go:embed html/*
var templates embed.FS

// BuildHTMLResults builds HTML results from vulnerability results.
func BuildHTMLResults(vulnResult *models.VulnerabilityResults) HTMLResult {
	var ecosystemMap = make(map[string][]HTMLSourceResult)
	var resultCount HTMLVulnCount

	for _, packageSource := range vulnResult.Results {
		sourceName := packageSource.Source.String()
		// Temporary workaround: it is a heuristic to ignore installed packages
		// which are already covered by OS-specific vulnerabilities.
		// This filtering should be handled by the container scanning process.
		// TODO(gongh@): Revisit this after container scanning supports comprehensive functionality.
		if strings.Contains(sourceName, "/usr/lib/") {
			continue
		}

		// Process vulnerabilities for each source
		sourceResult := processHTMLSource(packageSource)
		if sourceResult == nil {
			continue
		}

		ecosystemMap[sourceResult.Ecosystem] = append(ecosystemMap[sourceResult.Ecosystem], *sourceResult)
		updateCount(&resultCount, &sourceResult.HTMLVulnCount)
	}

	// Build the final result
	return buildHTMLResult(ecosystemMap, resultCount)
}

// processHTMLSource processes a single source (lockfile or artifact) and returns an SourceResult.
func processHTMLSource(packageSource models.PackageSource) *HTMLSourceResult {
	var allVulns []HTMLVulnResult
	var calledPackages = make(map[string]bool)
	var uncalledPackages = make(map[string]bool)
	var uncalledVulnIDs = make(map[string]bool)
	var groupIDs = make(map[string]models.GroupInfo)
	ecosystemName := ""

	for _, vulnPkg := range packageSource.Packages {
		if ecosystemName == "" {
			ecosystemName = vulnPkg.Package.Ecosystem
		}

		// Process vulnerability groups and IDs to get called/uncalled information
		processVulnerabilityGroups(vulnPkg, groupIDs, uncalledVulnIDs, calledPackages, uncalledPackages)
		// Process vulnerabilities from one source package
		allVulns = append(allVulns, processVulnerabilities(vulnPkg)...)
	}

	// Split vulnerabilities into called and uncalled.
	// Only add one vulnerability per group
	ecosystemPrefix := models.Ecosystem(strings.Split(ecosystemName, ":")[0])
	packageResults := processPackageResults(allVulns, groupIDs, uncalledVulnIDs, ecosystemPrefix)
	var count HTMLVulnCount
	for index, packageResult := range packageResults {
		packageResults[index].Ecosystem = ecosystemName
		packageResults[index].Source = packageSource.Source.Path
		updateCount(&count, &packageResult.HTMLVulnCount)
	}

	return &HTMLSourceResult{
		Source:               packageSource.Source.String(),
		Ecosystem:            ecosystemName,
		PackageResults:       packageResults,
		CalledPackageCount:   len(calledPackages),
		UncalledPackageCount: len(uncalledPackages),
		HTMLVulnCount:        count,
	}
}

// processPackageResults converts vulnerability data for a source
// (e.g. lockfile, artifact) into a list of HTMLPackageResult objects.
//
// This function processes all vulnerabilities within a single source, organizing them
// into separate HTMLPackageResult objects for each package within that source.
//
// Args:
//
//	allVulns:        A slice of HTMLVulnResult, representing all vulnerabilities found.
//	groupIDs:        A map containing vulnerability group information, keyed by the
//	                 representative ID of each group.
//	uncalledVulnIDs: A set of vulnerability IDs that are considered uncalled.
//	ecosystemPrefix: The ecosystem prefix associated with the package.
//
// Returns:
//
//	A slice of HTMLPackageResult, one for each package in the source, each containing
//	detailed information about called and uncalled vulnerabilities within that package.
func processPackageResults(allVulns []HTMLVulnResult, groupIDs map[string]models.GroupInfo, uncalledVulnIDs map[string]bool, ecosystemPrefix models.Ecosystem) []HTMLPackageResult {
	packageResults := make(map[string]*HTMLPackageResult)
	for _, vuln := range allVulns {
		groupInfo, isIndex := groupIDs[vuln.Summary.ID]
		if !isIndex {
			// We only display one vulnerability from one group
			continue
		}

		// Add group IDs info
		if len(groupInfo.IDs) > 1 {
			vuln.Detail.GroupIDs = groupInfo.IDs[1:]
		}

		packageName := vuln.Summary.PackageName
		packageResult, exist := packageResults[packageName]
		var packageDetail HTMLPackageLayerDetail
		if vuln.Detail.LayerCommand != "" {
			packageDetail = HTMLPackageLayerDetail{
				LayerCommand:        vuln.Detail.LayerCommand,
				LayerID:             vuln.Detail.LayerID,
				LayerCommandTooltip: vuln.Detail.LayerCommandTooltip,
				InBaseImage:         vuln.Detail.InBaseImage,
			}
		}

		if !exist {
			packageResult = &HTMLPackageResult{
				Name:                   packageName,
				HTMLPackageLayerDetail: packageDetail,
			}
			packageResults[packageName] = packageResult
		}

		// Get the max severity from groupInfo and increase the count
		vuln.Summary.SeverityScore = groupInfo.MaxSeverity
		rating, _ := severity.CalculateRating(vuln.Summary.SeverityScore)
		vuln.Summary.SeverityRating = string(rating)
		if vuln.Summary.SeverityRating == UnknownRating {
			vuln.Summary.SeverityScore = "N/A"
		}

		if _, isUncalled := uncalledVulnIDs[vuln.Summary.ID]; isUncalled {
			packageResult.UncalledVulns = append(packageResult.UncalledVulns, vuln)
			packageResult.HTMLVulnCount.Uncalled = len(packageResult.UncalledVulns)

			continue
		}

		packageResult.CalledVulns = append(packageResult.CalledVulns, vuln)
		packageResult.HTMLVulnCount.Called = len(packageResult.CalledVulns)
		addCount(&packageResult.HTMLVulnCount, vuln.Summary.SeverityRating)
		if vuln.Summary.FixedVersion == UnfixedDescription {
			packageResult.HTMLVulnCount.UnFixed += 1
		} else {
			packageResult.HTMLVulnCount.Fixed += 1
		}
	}

	results := make([]HTMLPackageResult, 0, len(packageResults))
	for _, result := range packageResults {
		if len(result.CalledVulns) > 0 {
			result.InstalledVersion = result.CalledVulns[0].Summary.InstalledVersion
			result.FixedVersion = getMaxFixedVersion(ecosystemPrefix, result.CalledVulns)
		} else {
			result.InstalledVersion = result.UncalledVulns[0].Summary.InstalledVersion
			result.FixedVersion = getMaxFixedVersion(ecosystemPrefix, result.UncalledVulns)
		}

		results = append(results, *result)
	}

	// Sort packageResults to ensure consistent output
	slices.SortFunc(results, func(a, b HTMLPackageResult) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.InstalledVersion, b.InstalledVersion),
		)
	})

	return results
}

// processVulnerabilities converts each vulnerability for a source package
// to an HTMLVulnResult
func processVulnerabilities(vulnPkg models.PackageVulns) []HTMLVulnResult {
	vulnResults := make([]HTMLVulnResult, len(vulnPkg.Vulnerabilities))
	for i, vuln := range vulnPkg.Vulnerabilities {
		// Sort aliases to make sure CVE show at the first
		slices.SortFunc(vuln.Aliases, identifiers.IDSortFunc)
		vulnDetails := HTMLVulnResultDetail{
			Aliases: vuln.Aliases,
		}

		if vulnPkg.Package.ImageOrigin != nil {
			vulnDetails.LayerCommand, vulnDetails.LayerCommandTooltip = formatLayerCommand(vulnPkg.Package.ImageOrigin.OriginCommand)
			vulnDetails.LayerID = vulnPkg.Package.ImageOrigin.LayerID
			vulnDetails.InBaseImage = vulnPkg.Package.ImageOrigin.InBaseImage
		}

		fixedVersion := getFixVersion(vuln.Affected, vulnPkg.Package.Version, vulnPkg.Package.Name, models.Ecosystem(vulnPkg.Package.Ecosystem))

		vulnResults[i] = HTMLVulnResult{
			Summary: HTMLVulnResultSummary{
				ID:               vuln.ID,
				PackageName:      vulnPkg.Package.Name,
				InstalledVersion: vulnPkg.Package.Version,
				FixedVersion:     fixedVersion,
			},
			Detail: vulnDetails,
		}
	}

	return vulnResults
}

// processVulnerabilityGroups processes package group information and populates the
// groupIDs, calledPackages, and uncalledPackages maps.
//
// Args:
//
//	vulnPkg:          Contains vulnerability information for a single source package.
//	groupIDs:         Adds sorted group IDs in vulnPkg to this map, keyed by the
//	                  representative ID of the group.
//	uncalledVulnIDs:  Records whether a vulnerability group is uncalled.
//	calledPackages:   Records whether a package has called vulnerability.
//	uncalledPackages: Records whether a package has uncalled vulnerability.
func processVulnerabilityGroups(vulnPkg models.PackageVulns, groupIDs map[string]models.GroupInfo, uncalledVulnIDs, calledPackages, uncalledPackages map[string]bool) {
	for _, group := range vulnPkg.Groups {
		slices.SortFunc(group.IDs, identifiers.IDSortFunc)
		representID := group.IDs[0]
		groupIDs[representID] = group
		if !group.IsCalled() {
			uncalledVulnIDs[representID] = true
			uncalledPackages[vulnPkg.Package.Name] = true
		} else {
			calledPackages[vulnPkg.Package.Name] = true
		}
	}
}

// buildHTMLResult builds the final HTMLResult object from the ecosystem map and total vulnerability count.
func buildHTMLResult(ecosystemMap map[string][]HTMLSourceResult, resultCount HTMLVulnCount) HTMLResult {
	var ecosystemResults []HTMLEcosystemResult
	var osResults []HTMLEcosystemResult
	for ecosystem, sources := range ecosystemMap {
		ecosystemResult := HTMLEcosystemResult{
			Ecosystem: ecosystem,
			Sources:   sources,
		}

		if isOSImage(ecosystem) {
			ecosystemResult.IsOS = true
			osResults = append(osResults, ecosystemResult)
		} else {
			ecosystemResults = append(ecosystemResults, ecosystemResult)
		}
	}

	// Sort ecosystemResults to ensure consistent output
	slices.SortFunc(ecosystemResults, func(a, b HTMLEcosystemResult) int {
		return cmp.Compare(a.Ecosystem, b.Ecosystem)
	})

	ecosystemResults = append(ecosystemResults, osResults...)

	isContainerScanning := false
	layers := getAllLayers(ecosystemResults)
	if len(layers) > 0 {
		isContainerScanning = true
	}
	vulnTypeCount := getHTMLVulnTypeCount(ecosystemResults)

	return HTMLResult{
		EcosystemResults:    ecosystemResults,
		HTMLVulnCount:       resultCount,
		IsContainerScanning: isContainerScanning,
		AllLayers:           layers,
		HTMLVulnTypeCount:   vulnTypeCount,
	}
}

func getHTMLVulnTypeCount(result []HTMLEcosystemResult) HTMLVulnTypeCount {
	var vulnCount HTMLVulnTypeCount

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			if ecosystem.IsOS {
				vulnCount.OS += source.HTMLVulnCount.Called
			} else {
				vulnCount.Project += source.HTMLVulnCount.Called
			}
			vulnCount.Uncalled += source.HTMLVulnCount.Uncalled
		}
	}

	vulnCount.All = vulnCount.OS + vulnCount.Project

	return vulnCount
}

func getAllLayers(result []HTMLEcosystemResult) []HTMLLayerInfo {
	layerMap := make(map[string]string)
	layerCount := make(map[string]HTMLVulnCount)
	layerIndex := 0

	for _, ecosystem := range result {
		for _, source := range ecosystem.Sources {
			for _, packageInfo := range source.PackageResults {
				layerID := packageInfo.HTMLPackageLayerDetail.LayerID
				layerCommand := packageInfo.HTMLPackageLayerDetail.LayerCommand

				// Check if this layer ID and command combination is already in the map
				if _, ok := layerMap[layerID]; !ok {
					var resultCount HTMLVulnCount
					updateCount(&resultCount, &packageInfo.HTMLVulnCount)
					layerMap[layerID] = layerCommand // Store the layer ID and command
					layerCount[layerID] = resultCount
					layerIndex++
				} else {
					resultCount := layerCount[layerID]
					updateCount(&resultCount, &packageInfo.HTMLVulnCount)
					layerCount[layerID] = resultCount
				}
			}
		}
	}

	// Convert the map to a slice of LayerInfo
	layers := make([]HTMLLayerInfo, 0, len(layerMap))
	i := 0
	for layerID, layerCommand := range layerMap {
		if layerCommand == "" {
			continue
		}
		layers = append(layers, HTMLLayerInfo{
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

func updateCount(original *HTMLVulnCount, newAdded *HTMLVulnCount) {
	original.Critical += newAdded.Critical
	original.High += newAdded.High
	original.Medium += newAdded.Medium
	original.Low += newAdded.Low
	original.Unknown += newAdded.Unknown
	original.Called += newAdded.Called
	original.Uncalled += newAdded.Uncalled
	original.Fixed += newAdded.Fixed
	original.UnFixed += newAdded.UnFixed
}

func addCount(resultCount *HTMLVulnCount, typeName string) {
	switch typeName {
	case "CRITICAL":
		resultCount.Critical += 1
	case "HIGH":
		resultCount.High += 1
	case "MEDIUM":
		resultCount.Medium += 1
	case "LOW":
		resultCount.Low += 1
	case "UNKNOWN":
		resultCount.Unknown += 1
	}
}

func isOSImage(ecosystem string) bool {
	for _, image := range osEcosystems {
		if strings.HasPrefix(ecosystem, image) {
			return true
		}
	}

	return false
}

// uniqueIndex creates a function that generates unique indices for HTML elements.
// It takes an integer pointer as input and increments the integer's value each time the
// returned function is called. This ensures that each call to the returned function
// produces a different index, even when called concurrently from multiple goroutines.
func uniqueIndex(index *int) func() int {
	return func() int {
		*index += 1
		return *index
	}
}

// getFixVersion returns the lowest fixed version for a given package and
// its current installed version, considering the affected ranges. If no fix is
// available, it returns "No fix available".
func getFixVersion(allAffected []models.Affected, installedVersion string, installedPackage string, ecosystem models.Ecosystem) string {
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

// getMaxFixedVersion determines the highest version that resolves the most known vulnerabilities for a package.
func getMaxFixedVersion(ecosystemPrefix models.Ecosystem, allVulns []HTMLVulnResult) string {
	maxFixVersion := ""
	var vp semantic.Version
	for _, vuln := range allVulns {
		if vuln.Summary.FixedVersion == VersionUnsupported {
			return UnfixedDescription
		}

		// Skip vulnerabilities without a fixed version.
		if vuln.Summary.FixedVersion == UnfixedDescription {
			continue
		}

		if maxFixVersion == "" {
			maxFixVersion = vuln.Summary.FixedVersion
			vp = semantic.MustParse(maxFixVersion, ecosystemPrefix)

			continue
		}

		// Update if the current vulnerability's fixed version is higher
		if vp.CompareStr(vuln.Summary.FixedVersion) < 0 {
			maxFixVersion = vuln.Summary.FixedVersion
			vp = semantic.MustParse(maxFixVersion, ecosystemPrefix)
		}
	}

	// Default to UnfixedDescription if no fix version is found.
	if maxFixVersion == "" {
		maxFixVersion = UnfixedDescription
	}

	return maxFixVersion
}

func getAllPackageResults(ecosystemResults []HTMLEcosystemResult) []HTMLPackageResult {
	var results []HTMLPackageResult
	for _, ecosystemResult := range ecosystemResults {
		for _, sourceResult := range ecosystemResult.Sources {
			results = append(results, sourceResult.PackageResults...)
		}
	}

	return results
}

// formatLayerCommand formats the layer command output for better readability.
// It replaces the unreadable file ID with "UNKNOWN" and extracting the ID separately.
func formatLayerCommand(command string) (string, string) {
	re := cachedregexp.MustCompile(`(dir|file):([a-f0-9]+)`)
	match := re.FindStringSubmatch(command)

	if len(match) > 2 {
		prefix := match[1] // Capture "dir" or "file"
		hash := match[2]   // Capture the hash ID
		newCommand := re.ReplaceAllString(command, prefix+":UNKNOWN")

		return newCommand, "File ID: " + hash
	}

	return command, ""
}

func PrintHTMLResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	htmlResult := BuildHTMLResults(vulnResult)
	vulnIndex := 0

	// Parse embedded templates
	funcMap := template.FuncMap{
		"uniqueID":             uniqueIndex(&vulnIndex),
		"getAllPackageResults": getAllPackageResults,
		"join":                 strings.Join,
		"toLower":              strings.ToLower,
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templates, TemplateDir))

	// Execute template
	return tmpl.ExecuteTemplate(outputWriter, "report_template.html", htmlResult)
}
