package reporter

import (
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/pkg/models"
)

const (
	FormatTable         = "table"
	FormatHTML          = "html"
	FormatVertical      = "vertical"
	FormatJSON          = "json"
	FormatMarkdown      = "markdown"
	FormatSARIF         = "sarif"
	FormatGHAnnotations = "gh-annotations"
	FormatCycloneDX14   = "cyclonedx-1-4"
	FormatCycloneDX15   = "cyclonedx-1-5"
	FormatCycloneDX16   = "cyclonedx-1-6"
	FormatCycloneDX17   = "cyclonedx-1-7"
	FormatSPDX23        = "spdx-2-3"
	FormatGitLab        = "gitlab"
)

func Format() []string {
	return []string{
		FormatTable,
		FormatHTML,
		FormatVertical,
		FormatJSON,
		FormatMarkdown,
		FormatSARIF,
		FormatGHAnnotations,
		FormatCycloneDX14,
		FormatCycloneDX15,
		FormatCycloneDX16,
		FormatCycloneDX17,
		FormatSPDX23,
		FormatGitLab,
	}
}

func newResultPrinter(format string, writer io.Writer, terminalWidth int, showAllVulns bool) (resultPrinter, error) {
	switch format {
	case FormatHTML:
		return &htmlReporter{writer}, nil
	case FormatJSON:
		return &jsonReporter{writer}, nil
	case FormatVertical:
		return &verticalReporter{writer, terminalWidth, showAllVulns}, nil
	case FormatTable:
		return &tableReporter{writer, false, terminalWidth, showAllVulns}, nil
	case FormatMarkdown:
		return &tableReporter{writer, true, terminalWidth, showAllVulns}, nil
	case FormatSARIF:
		return &sarifReporter{writer}, nil
	case FormatGHAnnotations:
		return &ghAnnotationsReporter{writer}, nil
	case FormatCycloneDX14:
		return &cycloneDXReporter{writer, models.CycloneDXVersion14}, nil
	case FormatCycloneDX15:
		return &cycloneDXReporter{writer, models.CycloneDXVersion15}, nil
	case FormatCycloneDX16:
		return &cycloneDXReporter{writer, models.CycloneDXVersion16}, nil
	case FormatCycloneDX17:
		return &cycloneDXReporter{writer, models.CycloneDXVersion17}, nil
	case FormatSPDX23:
		return &spdxReporter{writer}, nil
	case FormatGitLab:
		return &gitlabReporter{writer}, nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}
