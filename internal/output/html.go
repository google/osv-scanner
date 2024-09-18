package output

import (
	"embed"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/google/osv-scanner/internal/semantic"
	"github.com/google/osv-scanner/internal/utility/severity"
	"github.com/google/osv-scanner/pkg/models"
)

type HTMLResult struct {
	TotalCount       int
	EcosystemResults []EcosystemResult
}

type EcosystemResult struct {
	Ecosystem string
	Artifacts []ArtifactResult
	isOS      bool
}

type ArtifactResult struct {
	Source        string
	Ecosystem     string
	CalledVulns   []HTMLVulnResult
	UncalledVulns []HTMLVulnResult
	VulnCount     [2]int
	PackageCount  [2]int
}

type HTMLVulnResult struct {
	Summary HTMLVulnResultSummary
	Detail  map[string]string
}

type HTMLVulnResultSummary struct {
	Id               string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	Severity         string
}

// supportedBaseImages lists the supported OS base images for container scanning.
var baseImages = []string{"Debian", "Alpine", "Ubuntu"}

//go:embed html/*
var templates embed.FS

var templateDir = "html/*"

// BuildHTMLResults builds HTML results from vulnerability results.
func BuildHTMLResults(vulnResult *models.VulnerabilityResults) HTMLResult {
	var ecosystemMap = make(map[string][]ArtifactResult)
	totalVuln := 0

	for _, packageSource := range vulnResult.Results {
		sourceName := packageSource.Source.String()
		if strings.Contains(sourceName, "/usr/lib/") {
			continue
		}

		// Process vulnerabilities for each source
		artifactResult := processSource(packageSource)
		if artifactResult == nil {
			continue
		}

		artifactList, ok := ecosystemMap[artifactResult.Ecosystem]
		if ok {
			ecosystemMap[artifactResult.Ecosystem] = append(artifactList, *artifactResult)
		} else {
			ecosystemMap[artifactResult.Ecosystem] = []ArtifactResult{*artifactResult}
		}

		totalVuln += len(artifactResult.CalledVulns)
	}

	// Build the final result
	return buildHTMLResult(ecosystemMap, totalVuln)
}

// processSource processes a single source (lockfile or artifact) and returns an ArtifactResult.
func processSource(packageSource models.PackageSource) *ArtifactResult {
	var allVulns []HTMLVulnResult
	var calledPackages = make(map[string]bool)
	var uncalledPackages = make(map[string]bool)
	var uncalledVulnIds = make(map[string]bool)
	ecosystemName := ""

	for _, vulnPkg := range packageSource.Packages {
		if ecosystemName == "" {
			ecosystemName = vulnPkg.Package.Ecosystem
		}

		// Process vulnerability groups and IDs to get uncalled information
		processVulnerabilityGroups(vulnPkg, uncalledVulnIds, calledPackages, uncalledPackages)

		// Process vulnerabilities from one source package
		allVulns = append(allVulns, processVulnerabilities(vulnPkg)...)
	}

	// Split vulnerabilities into called and uncalled
	calledVulns, uncalledVulns := splitVulnerabilities(allVulns, uncalledVulnIds)

	return &ArtifactResult{
		Source:        packageSource.Source.String(),
		Ecosystem:     ecosystemName,
		CalledVulns:   calledVulns,
		UncalledVulns: uncalledVulns,
		VulnCount:     [2]int{len(calledVulns), len(uncalledVulns)},
		PackageCount:  [2]int{len(calledPackages), len(uncalledPackages)},
	}
}

// splitVulnerabilities splits the given vulnerabilities into called and uncalled
// based on the uncalledVulnIds map.
func splitVulnerabilities(allVulns []HTMLVulnResult, uncalledVulnIds map[string]bool) ([]HTMLVulnResult, []HTMLVulnResult) {
	var calledVulns []HTMLVulnResult
	var uncalledVulns []HTMLVulnResult
	for _, vuln := range allVulns {
		if _, isUncalled := uncalledVulnIds[vuln.Summary.Id]; isUncalled {
			uncalledVulns = append(uncalledVulns, vuln)
		} else {
			calledVulns = append(calledVulns, vuln)
		}
	}
	return calledVulns, uncalledVulns
}

// processVulnerabilities processes vulnerabilities for a package
// and returns a slice of HTMLVulnResult.
func processVulnerabilities(vulnPkg models.PackageVulns) []HTMLVulnResult {
	var vulnResults []HTMLVulnResult
	for _, vuln := range vulnPkg.Vulnerabilities {
		aliases := strings.Join(vuln.Aliases, ", ")
		vulnDetails := map[string]string{
			"aliases":     aliases,
			"description": vuln.Details,
		}
		if vulnPkg.Package.ImageOrigin != nil {
			vulnDetails["layerCommand"] = vulnPkg.Package.ImageOrigin.OriginCommand
			vulnDetails["layerId"] = vulnPkg.Package.ImageOrigin.LayerID
			vulnDetails["inBaseImage"] = strconv.FormatBool(vulnPkg.Package.ImageOrigin.InBaseImage)
		}

		severityValue := "N/A"
		if len(vuln.Severity) > 0 {
			score, rating, _ := severity.CalculateOverallScore(vuln.Severity)
			severityValue = fmt.Sprintf("%s (%.1f)", rating, score)
		}

		fixedVersion := getFixVersion(vuln.Affected, vulnPkg.Package.Version, vulnPkg.Package.Name, models.Ecosystem(vulnPkg.Package.Ecosystem))

		vulnResults = append(vulnResults, HTMLVulnResult{
			Summary: HTMLVulnResultSummary{
				Id:               vuln.ID,
				PackageName:      vulnPkg.Package.Name,
				InstalledVersion: vulnPkg.Package.Version,
				FixedVersion:     fixedVersion,
				Severity:         severityValue,
			},
			Detail: vulnDetails,
		})
	}

	return vulnResults
}

// processVulnerabilityGroups processes vulnerability groups and IDs,
// populating the called and uncalled maps.
func processVulnerabilityGroups(vulnPkg models.PackageVulns, uncalledVulnIds map[string]bool, calledPackages map[string]bool, uncalledPackages map[string]bool) {
	for _, group := range vulnPkg.Groups {
		if !group.IsCalled() {
			for _, id := range group.IDs {
				uncalledVulnIds[id] = true
			}
			uncalledPackages[vulnPkg.Package.Name] = true
		} else {
			calledPackages[vulnPkg.Package.Name] = true
		}
	}
}

// buildHTMLResult builds the final HTMLResult object from the ecosystem map and total vulnerability count.
func buildHTMLResult(ecosystemMap map[string][]ArtifactResult, totalVuln int) HTMLResult {
	var ecosystemResults []EcosystemResult
	var osResults []EcosystemResult
	for ecosystem, artifacts := range ecosystemMap {
		ecosystemResult := EcosystemResult{
			Ecosystem: ecosystem,
			Artifacts: artifacts,
		}

		if isOSImage(ecosystem) {
			osResults = append(osResults, ecosystemResult)
		} else {
			ecosystemResults = append(ecosystemResults, ecosystemResult)
		}
	}

	ecosystemResults = append(ecosystemResults, osResults...)

	return HTMLResult{
		EcosystemResults: ecosystemResults,
		TotalCount:       totalVuln,
	}
}

func isOSImage(ecosystem string) bool {
	for _, image := range baseImages {
		if strings.HasPrefix(ecosystem, image) {
			return true
		}
	}

	return false
}

// formatString formats a camelCase string into a human readable string
// by adding spaces before uppercase letters.
func formatString(input string) string {
	// Add space before uppercase letters
	var result strings.Builder
	for i, r := range input {
		if i == 0 {
			result.WriteRune(unicode.ToUpper(r))
			continue
		}
		if i > 0 && unicode.IsUpper(r) {
			result.WriteRune(' ')
		}
		result.WriteRune(r)
	}
	return result.String()
}

// generateRandomNumber generates a random integer.
// It is used to create unique IDs in HTML templates.
func generateRandomNumber() int {
	return rand.Intn(1000)
}

// getFixVersion returns the lowest fixed version for a given package and
// its current installed version, considering the affected ranges. If no fix is
// available, it returns "No fix available".
func getFixVersion(allAffected []models.Affected, installedVersion string, installedPackage string, ecosystem models.Ecosystem) string {
	ecosystemPrefix := models.Ecosystem(strings.Split(string(ecosystem), ":")[0])
	vp := semantic.MustParse(installedVersion, ecosystemPrefix)
	minFixVersion := ""
	for _, affected := range allAffected {
		if affected.Package.Name == installedPackage && affected.Package.Ecosystem == ecosystem {
			for _, affectedRange := range affected.Ranges {
				for _, affectedEvent := range affectedRange.Events {
					if affectedEvent.Fixed == "" {
						continue
					}
					if vp.CompareStr(affectedEvent.Fixed) < 0 {
						if minFixVersion == "" || semantic.MustParse(affectedEvent.Fixed, ecosystemPrefix).CompareStr(minFixVersion) < 0 {
							minFixVersion = affectedEvent.Fixed
						}
					}
				}
			}
		}
	}

	if minFixVersion == "" {
		return "No fix available"
	}

	return minFixVersion
}

func PrintHTMLResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	htmlResult := BuildHTMLResults(vulnResult)

	// Parse embedded templates
	funcMap := template.FuncMap{
		"format": formatString,
		"random": generateRandomNumber,
	}
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templates, templateDir))

	// Execute template
	return tmpl.ExecuteTemplate(outputWriter, "report_template.html", htmlResult)
}
