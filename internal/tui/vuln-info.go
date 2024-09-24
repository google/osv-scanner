package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
	"github.com/charmbracelet/glamour/styles"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/muesli/reflow/wordwrap"
)

// ViewModel to display the details of a specific vulnerability
type vulnInfo struct {
	vuln        *resolution.Vulnerability
	chainGraphs []ChainGraph

	width  int
	height int
	cursor int

	numDetailLines int              // number of lines to show for details in the main view
	mdStyle        ansi.StyleConfig // markdown styling for details

	viewport    viewport.Model // used for scrolling onlyDetails & onlyGraphs views
	onlyDetails bool           // if the details screen is open
	onlyGraphs  bool           // if the affected screen is open
}

var (
	vulnInfoHeadingStyle = lipgloss.NewStyle().
				Bold(true).
				Width(10).
				MarginRight(2).
				Foreground(ColorPrimary)
	highlightedVulnInfoHeadingStyle = vulnInfoHeadingStyle.Reverse(true)
)

//revive:disable-next-line:unexported-return
func NewVulnInfo(vuln *resolution.Vulnerability) *vulnInfo {
	v := vulnInfo{
		vuln:           vuln,
		width:          ViewMinWidth,
		height:         ViewMinHeight,
		cursor:         0,
		numDetailLines: 5,
		viewport:       viewport.New(ViewMinWidth, 20),
	}
	v.viewport.KeyMap = viewport.KeyMap{
		Up:       Keys.Up,
		Down:     Keys.Down,
		PageUp:   Keys.Left,
		PageDown: Keys.Right,
	}

	// remove the padding/margins from the default markdown style
	if lipgloss.HasDarkBackground() {
		v.mdStyle = styles.DarkStyleConfig
	} else {
		v.mdStyle = styles.LightStyleConfig
	}
	*v.mdStyle.Document.Margin = 0
	v.mdStyle.Document.BlockPrefix = ""

	chains := append(slices.Clone(vuln.ProblemChains), vuln.NonProblemChains...)
	v.chainGraphs = FindChainGraphs(chains)

	return &v
}

func (v *vulnInfo) Resize(w, h int) {
	v.width = w
	v.height = h
	v.viewport.Width = w
	v.viewport.Height = h
	if v.onlyDetails {
		v.viewport.SetContent(v.detailsOnlyView())
	}
}

func (v *vulnInfo) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	if v.onlyDetails || v.onlyGraphs {
		if msg, ok := msg.(tea.KeyMsg); ok {
			if key.Matches(msg, Keys.Quit) {
				v.onlyDetails = false
				v.onlyGraphs = false

				return v, nil
			}
		}
		var cmd tea.Cmd
		v.viewport, cmd = v.viewport.Update(msg)

		return v, cmd
	}
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, Keys.Quit):
			return nil, nil
		case key.Matches(msg, Keys.Down):
			if v.cursor < 4 {
				v.cursor++
			}
		case key.Matches(msg, Keys.Up):
			if v.cursor > 0 {
				v.cursor--
			}
		case key.Matches(msg, Keys.Select):
			if v.cursor == 3 {
				v.onlyDetails = true
				v.viewport.SetContent(v.detailsOnlyView())
				v.viewport.GotoTop()
			}
			if v.cursor == 4 {
				v.onlyGraphs = true
				v.viewport.SetContent(v.graphOnlyView())
				v.viewport.GotoTop()
			}
		}
	}

	return v, nil
}

func (v *vulnInfo) View() string {
	if v.onlyDetails || v.onlyGraphs {
		return v.viewport.View()
	}

	detailWidth := v.width - (vulnInfoHeadingStyle.GetWidth() + vulnInfoHeadingStyle.GetMarginRight())

	vID := v.vuln.OSV.ID
	sev := RenderSeverity(v.vuln.OSV.Severity)
	sum := wordwrap.String(v.vuln.OSV.Summary, detailWidth)

	var det string
	r, err := glamour.NewTermRenderer(
		glamour.WithStyles(v.mdStyle),
		glamour.WithWordWrap(detailWidth),
	)
	if err == nil {
		det, err = r.Render(v.vuln.OSV.Details)
	}
	if err != nil {
		det = v.fallbackDetails(detailWidth)
	}
	det = lipgloss.NewStyle().MaxHeight(v.numDetailLines).Render(det)

	s := strings.Builder{}
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(0).Render("ID:"), vID))
	s.WriteString("\n")
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(1).Render("Severity:"), sev))
	s.WriteString("\n")
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(2).Render("Summary:"), sum))
	s.WriteString("\n")
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(3).Render("Details:"), det))
	s.WriteString("\n")
	s.WriteString(v.headingStyle(4).Render("Affected:"))
	s.WriteString("\n")
	if len(v.chainGraphs) == 0 {
		s.WriteString("ERROR: could not resolve any affected paths\n")
		return s.String()
	}
	s.WriteString(lipgloss.NewStyle().MaxWidth(v.width).Render(v.chainGraphs[0].String()))
	s.WriteString("\n")
	if len(v.chainGraphs) > 1 {
		s.WriteString(DisabledTextStyle.Render(fmt.Sprintf("+%d other paths", len(v.chainGraphs)-1)))
		s.WriteString("\n")
	}

	return s.String()
}

func (v *vulnInfo) detailsOnlyView() string {
	s := strings.Builder{}
	s.WriteString(vulnInfoHeadingStyle.Render("Details:"))
	s.WriteString("\n")
	var det string
	r, err := glamour.NewTermRenderer(
		glamour.WithStyles(v.mdStyle),
		glamour.WithWordWrap(v.width),
	)
	if err == nil {
		det, err = r.Render(v.vuln.OSV.Details)
	}
	if err != nil {
		det = v.fallbackDetails(v.width)
	}
	s.WriteString(det)

	return s.String()
}

func (v *vulnInfo) graphOnlyView() string {
	// TODO: some graphs still get clipped on the right side
	// need horizontal scrolling, but that's not supported by the bubbles viewport
	// and it's difficult to implement
	s := strings.Builder{}
	s.WriteString(vulnInfoHeadingStyle.Render("Affected:"))
	strs := make([]string, 0, 2*len(v.chainGraphs)) // 2x to include padding newlines between graphs
	for _, g := range v.chainGraphs {
		strs = append(strs, "\n", g.String())
	}
	s.WriteString(lipgloss.JoinVertical(lipgloss.Center, strs...))

	return s.String()
}

func (v *vulnInfo) headingStyle(idx int) lipgloss.Style {
	if idx == v.cursor {
		return highlightedVulnInfoHeadingStyle
	}

	return vulnInfoHeadingStyle
}

func (v *vulnInfo) fallbackDetails(width int) string {
	// Use raw details if markdown rendering fails for whatever reason
	return wordwrap.String(v.vuln.OSV.Details, width)
}
