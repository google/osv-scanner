package tui

import (
	"cmp"
	"fmt"
	"io"
	"slices"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/utility/severity"
	"github.com/muesli/reflow/truncate"
)

// A ViewModel list of vulnerabilities,
// selectable to show details
type vulnList struct {
	// There is a table model that could be used for this instead,
	// but there is much less control over the styling of the cells
	list.Model

	preamble     string    // text to write above vuln list
	currVulnInfo ViewModel // selected vulnerability

	delegate list.ItemDelegate // default item renderer
	blurred  bool              // whether the cursor should be hidden and input disabled
}

//revive:disable-next-line:unexported-return
func NewVulnList(vulns []*resolution.Vulnerability, preamble string) *vulnList {
	vl := vulnList{preamble: preamble}
	// Sort the vulns by descending severity, then ID
	vulns = slices.Clone(vulns)
	slices.SortFunc(vulns, func(a, b *resolution.Vulnerability) int {
		aScoreFloat, aRating, _ := severity.CalculateOverallScore(a.OSV.Severity)
		aScore := int(aScoreFloat * 10) // CVSS scores are only to 1dp
		if aRating == "UNKNOWN" {
			aScore = 999 // Sort unknown before critical
		}
		bScoreFloat, bRating, _ := severity.CalculateOverallScore(b.OSV.Severity)
		bScore := int(bScoreFloat * 10) // CVSS scores are only to 1dp
		if bRating == "UNKNOWN" {
			bScore = 999 // Sort unknown before critical
		}

		if c := cmp.Compare(aScore, bScore); c != 0 {
			return -c
		}

		return cmp.Compare(a.OSV.ID, b.OSV.ID)
	})
	items := make([]list.Item, 0, len(vulns))
	delegate := vulnListItemDelegate{idWidth: 0}
	for _, v := range vulns {
		items = append(items, vulnListItem{v})
		if w := lipgloss.Width(v.OSV.ID); w > delegate.idWidth {
			delegate.idWidth = w
		}
	}
	l := list.New(items, delegate, ViewMinWidth, ViewMinHeight-vl.preambleHeight())
	l.SetFilteringEnabled(false)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.DisableQuitKeybindings()
	l.KeyMap = list.KeyMap{
		CursorUp:   Keys.Up,
		CursorDown: Keys.Down,
		NextPage:   Keys.Right,
		PrevPage:   Keys.Left,
	}
	l.Styles.TitleBar = lipgloss.NewStyle().PaddingLeft(2).Width(ViewMinWidth).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	l.Styles.Title = lipgloss.NewStyle()
	l.Title = fmt.Sprintf("%s  %s  %s",
		lipgloss.NewStyle().Width(delegate.idWidth).Render("VULN ID"),
		" SEV ", // intentional spacing, scores always 5 wide
		"SUMMARY",
	)
	vl.Model = l
	vl.delegate = delegate

	return &vl
}

func (v *vulnList) preambleHeight() int {
	if len(v.preamble) == 0 {
		return 0
	}

	return lipgloss.Height(v.preamble)
}

func (v *vulnList) Resize(w, h int) {
	v.SetWidth(w)
	v.SetHeight(h - v.preambleHeight())
	v.Styles.TitleBar = v.Styles.TitleBar.Width(w)
	if v.currVulnInfo != nil {
		v.currVulnInfo.Resize(w, h)
	}
}

func (v *vulnList) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	if v.blurred {
		return v, nil
	}
	var cmd tea.Cmd
	if v.currVulnInfo != nil {
		v.currVulnInfo, cmd = v.currVulnInfo.Update(msg)
		return v, cmd
	}
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, Keys.Quit):
			return v, CloseViewModel
		case key.Matches(msg, Keys.Select):
			vuln := v.Model.SelectedItem().(vulnListItem)
			v.currVulnInfo = NewVulnInfo(vuln.Vulnerability)
			v.currVulnInfo.Resize(v.Width(), v.Height())

			return v, nil
		}
	}
	if v.currVulnInfo == nil {
		v.Model, cmd = v.Model.Update(msg)
	}

	return v, cmd
}

func (v *vulnList) View() string {
	if v.currVulnInfo != nil {
		return v.currVulnInfo.View()
	}
	str := v.Model.View()
	if len(v.preamble) > 0 {
		str = lipgloss.JoinVertical(lipgloss.Left, v.preamble, str)
	}

	return str
}

func (v *vulnList) Blur() {
	v.blurred = true
	v.SetDelegate(blurredDelegate{v.delegate})
}

func (v *vulnList) Focus() {
	v.blurred = false
	v.SetDelegate(v.delegate)
}

// Helpers for the list.Model
type vulnListItem struct {
	*resolution.Vulnerability
}

func (v vulnListItem) FilterValue() string {
	return v.OSV.ID
}

type vulnListItemDelegate struct {
	idWidth int
}

func (d vulnListItemDelegate) Height() int                         { return 1 }
func (d vulnListItemDelegate) Spacing() int                        { return 0 }
func (d vulnListItemDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (d vulnListItemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	vuln, ok := listItem.(vulnListItem)
	if !ok {
		return
	}
	cursor := " "
	idStyle := lipgloss.NewStyle().Width(d.idWidth).Align(lipgloss.Left)
	if index == m.Index() {
		cursor = SelectedTextStyle.Render(">")
		idStyle = idStyle.Inherit(SelectedTextStyle)
	}
	id := idStyle.Render(vuln.OSV.ID)
	severity := RenderSeverityShort(vuln.OSV.Severity)
	str := fmt.Sprintf("%s %s  %s  ", cursor, id, severity)
	fmt.Fprint(w, str)
	fmt.Fprint(w, truncate.StringWithTail(vuln.OSV.Summary, uint(m.Width()-lipgloss.Width(str)), "…")) //nolint:gosec
}

// workaround item delegate wrapper to stop the selected item from being shown as selected
type blurredDelegate struct {
	list.ItemDelegate
}

func (d blurredDelegate) Render(w io.Writer, m list.Model, _ int, listItem list.Item) {
	d.ItemDelegate.Render(w, m, -1, listItem)
}
