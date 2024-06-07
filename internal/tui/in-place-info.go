package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
)

// A ViewModel showing the table of package upgrades and fixed vulnerabilities, for in-place upgrades.
// Pressing 'enter' on a row shows the vulnerability details
type inPlaceInfo struct {
	table.Model

	vulns        []*resolution.ResolutionVuln
	currVulnInfo ViewModel

	width  int
	height int
}

func NewInPlaceInfo(res remediation.InPlaceResult) *inPlaceInfo {
	info := inPlaceInfo{width: ViewMinWidth, height: ViewMinHeight} // placeholder dimensions
	cols := []table.Column{
		{Title: "PACKAGE"},
		{Title: "VERSION CHANGE"},
		{Title: "FIXED VULN"},
	}
	for i := range cols {
		cols[i].Width = lipgloss.Width(cols[i].Title)
	}

	rows := make([]table.Row, 0, len(res.Patches))
	for _, patch := range res.Patches {
		// Make a new row for each vulnerability
		// I wanted to have this as one entry with multiple vulnerabilities,
		// but tables don't let you have multi-line rows.

		// Put the package name only on the first row
		row := table.Row{
			patch.Pkg.Name,
			fmt.Sprintf("%s → %s", patch.OrigVersion, patch.NewVersion),
			patch.ResolvedVulns[0].Vulnerability.ID,
		}
		// Set each column to their widest element
		for i, s := range row {
			if w := lipgloss.Width(s); w > cols[i].Width {
				cols[i].Width = w
			}
		}
		rows = append(rows, row)
		info.vulns = append(info.vulns, &patch.ResolvedVulns[0])

		// use blank package name / bump for other vulns from same patch
		for i, v := range patch.ResolvedVulns[1:] {
			row := table.Row{
				"",
				"",
				v.Vulnerability.ID,
			}
			rows = append(rows, row)
			info.vulns = append(info.vulns, &patch.ResolvedVulns[i+1])
			if w := lipgloss.Width(row[2]); w > cols[2].Width {
				cols[2].Width = w
			}
		}
	}

	// centre the version change strings
	cols[1].Title = lipgloss.PlaceHorizontal(cols[1].Width, lipgloss.Center, cols[1].Title)
	for _, row := range rows {
		row[1] = lipgloss.PlaceHorizontal(cols[1].Width, lipgloss.Center, row[1])
	}

	st := table.DefaultStyles()
	st.Header = st.Header.Bold(false).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	st.Selected = st.Selected.Foreground(ColorPrimary)

	info.Model = table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithWidth(info.width),
		table.WithHeight(info.height),
		table.WithFocused(true),
		table.WithStyles(st),
		table.WithKeyMap(table.KeyMap{
			LineUp:   Keys.Up,
			LineDown: Keys.Down,
			PageUp:   Keys.Left,
			PageDown: Keys.Right,
		}),
	)

	return &info
}

func (ip *inPlaceInfo) Resize(w, h int) {
	ip.width = w
	ip.height = h
	ip.SetWidth(w)
	ip.SetHeight(h)
	if ip.currVulnInfo != nil {
		ip.currVulnInfo.Resize(w, h)
	}
}

func (ip *inPlaceInfo) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	var cmd tea.Cmd
	if ip.currVulnInfo != nil {
		ip.currVulnInfo, cmd = ip.currVulnInfo.Update(msg)
		return ip, cmd
	}
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, Keys.Quit):
			return ip, CloseViewModel
		case key.Matches(msg, Keys.Select):
			vuln := ip.vulns[ip.Model.Cursor()]
			ip.currVulnInfo = NewVulnInfo(vuln)
			ip.currVulnInfo.Resize(ip.Width(), ip.Height())

			return ip, nil
		}
	}
	ip.Model, cmd = ip.Model.Update(msg)

	return ip, cmd
}

func (ip *inPlaceInfo) View() string {
	if ip.currVulnInfo != nil {
		return ip.currVulnInfo.View()
	}
	// place the table in the centre of the view
	return lipgloss.Place(ip.width, ip.height, lipgloss.Center, lipgloss.Center, ip.Model.View())
}
