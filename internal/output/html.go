package output

import (
	"embed"
	"html/template"
	"io"
	"strings"

	"github.com/google/osv-scanner/v2/internal/utility/results"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// TemplateDir is the directory containing the HTML templates
const TemplateDir = "html/*"

//go:embed html/*
var templates embed.FS

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

func formatSlice(slice []string) string {
	return strings.Join(slice, ", ")
}

func formatLicense(slice []models.License) string {
	stringSlice := make([]string, len(slice))
	for i, license := range slice {
		stringSlice[i] = string(license)
	}

	return formatSlice(stringSlice)
}

func formatRating(rating severity.Rating) string {
	return strings.ToLower(string(rating))
}

type VulnTableEntryArgument struct {
	Element  VulnResult
	IsHidden bool
}

func buildVulnTableEntryArgument(element VulnResult, isHidden bool) VulnTableEntryArgument {
	return VulnTableEntryArgument{
		IsHidden: isHidden,
		Element:  element,
	}
}

func hasOSResult(ecosystems []EcosystemResult) bool {
	for _, ecosystem := range ecosystems {
		if ecosystem.IsOS {
			return true
		}
	}

	return false
}

func PrintHTMLResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	// htmlResult := BuildHTMLResults(vulnResult)
	result := BuildResults(vulnResult)
	vulnIndex := 0

	// Parse embedded templates
	funcMap := template.FuncMap{
		"uniqueID":     uniqueIndex(&vulnIndex),
		"join":         strings.Join,
		"formatRating": formatRating,
		"add": func(a, b int) int {
			return a + b
		},
		"getFilteredVulnReasons":      getFilteredVulnReasons,
		"getBaseImageName":            getBaseImageName,
		"formatSlice":                 formatSlice,
		"formatLayerCommand":          formatLayerCommand,
		"buildVulnTableEntryArgument": buildVulnTableEntryArgument,
		"formatLicense":               formatLicense,
		"hasOSResult":                 hasOSResult,
		"GetShortCommit":              results.GetShortCommit,
		"isOSResult":                  isOSResult,
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templates, TemplateDir))

	// Execute template
	return tmpl.ExecuteTemplate(outputWriter, "report_template.gohtml", result)
}
