package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var (
	severityColor = map[string]lipgloss.Color{
		"UNKNOWN":  lipgloss.Color("243"), // grey
		"NONE":     lipgloss.Color("243"), // grey
		"LOW":      lipgloss.Color("28"),  // green
		"MEDIUM":   lipgloss.Color("208"), // orange
		"HIGH":     lipgloss.Color("160"), // red
		"CRITICAL": lipgloss.Color("88"),  // dark red
	}
	severityStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")). // white
			Bold(true).
			Align(lipgloss.Center)
)

func RenderSeverity(severities []osvschema.Severity) string {
	text := "UNKNOWN"
	score, rating, _ := severity.CalculateOverallScore(severities)
	if rating != "UNKNOWN" {
		text = fmt.Sprintf("%1.1f %s", score, rating)
	}

	return severityStyle.Width(16).Background(severityColor[rating]).Render(text)
}

func RenderSeverityShort(severities []osvschema.Severity) string {
	score, rating, _ := severity.CalculateOverallScore(severities)
	scoreStr := fmt.Sprintf("%1.1f", score)
	if rating == "UNKNOWN" {
		scoreStr = "???"
	}

	return severityStyle.Width(5).Background(severityColor[rating]).Render(scoreStr)
}
