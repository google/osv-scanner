package fix

import (
	"fmt"
	"slices"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/tui"
)

type stateChooseInPlacePatches struct {
	stateInPlace *stateInPlaceResult

	table      table.Model     // in-place table to render
	patchIdx   []int           // for each flattened patch, its index into unflattened patches
	vulnsInfos []tui.ViewModel // vulns info views corresponding to each flattened patch

	focusedInfo tui.ViewModel // the infoview that is currently focused, nil if not focused

	viewWidth int // width for rendering (same as model.mainViewWidth)
}

func (st *stateChooseInPlacePatches) Init(m model) tea.Cmd {
	// pre-computation of flattened patches and vulns
	for idx, p := range m.inPlaceResult.Patches {
		for i := range p.ResolvedVulns {
			st.patchIdx = append(st.patchIdx, idx)
			st.vulnsInfos = append(st.vulnsInfos, tui.NewVulnInfo(&p.ResolvedVulns[i]))
		}
	}

	// grab the table out of the InPlaceInfo, so it looks consistent
	// TODO: Re-use this in a less hacky way
	st.table = tui.NewInPlaceInfo(*m.inPlaceResult).Model
	// insert the select/deselect all row, and a placeholder row for the 'done' line
	r := st.table.Rows()
	r = slices.Insert(r, 0, table.Row{"", "", ""})
	r = append(r, table.Row{"", "", ""})
	st.table.SetRows(r)

	st.updateTableRows(m)
	st.Resize(m.mainViewWidth, m.mainViewHeight)
	st.ResizeInfo(m.infoViewWidth, m.infoViewHeight)

	return nil
}

func (st *stateChooseInPlacePatches) Update(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, tui.Keys.SwitchView):
			if st.IsInfoFocused() {
				st.focusedInfo = nil
				st.table.Focus()
			} else if view, canFocus := st.currentInfoView(); canFocus {
				st.focusedInfo = view
				st.table.Blur() // ignore key presses when the info view is focused
			}
		case st.IsInfoFocused():
			st.focusedInfo, cmd = st.focusedInfo.Update(msg)
			// VulnInfo returns nil as the model when it wants to exit, instead of the CloseViewModel Cmd
			// if it quits, we need to re-focus the table
			if st.focusedInfo == nil {
				st.table.Focus()
			}
		case key.Matches(msg, tui.Keys.Quit):
			// go back to in-place results
			m.st = st.stateInPlace
			return m, nil

		case key.Matches(msg, tui.Keys.Select):
			if st.table.Cursor() == len(st.table.Rows())-1 { // hit enter on done line
				// go back to in-place results
				m.st = st.stateInPlace
				return m, nil
			}
			if st.table.Cursor() == 0 { // select/deselect all
				// if nothing is selected, set everything to true, otherwise set everything to false
				selection := !slices.Contains(st.stateInPlace.selectedChanges, true)
				for i := range st.stateInPlace.selectedChanges {
					st.stateInPlace.selectedChanges[i] = selection
				}
			} else {
				st.toggleSelection(st.table.Cursor() - 1)
			}
			st.updateTableRows(m)
		}
	}
	// update the table
	t, c := st.table.Update(msg)
	st.table = t

	return m, tea.Batch(cmd, c)
}

func (st *stateChooseInPlacePatches) View(_ model) string {
	tableStr := lipgloss.PlaceHorizontal(st.viewWidth, lipgloss.Center, st.table.View())
	return lipgloss.JoinVertical(lipgloss.Left,
		tableStr,
		tui.RenderSelectorOption(st.table.Cursor() == len(st.table.Rows())-1, " > ", "%s", "Done"),
	)
}

func (st *stateChooseInPlacePatches) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

func (st *stateChooseInPlacePatches) updateTableRows(m model) {
	// update the checkbox for each row
	rows := st.table.Rows()
	anySelected := false
	for i, pIdx := range st.patchIdx {
		// don't render a checkbox on the empty lines
		if rows[i+1][0] == "" {
			continue
		}
		var checkBox string
		if st.stateInPlace.selectedChanges[pIdx] {
			checkBox = "[x]"
			anySelected = true
		} else {
			checkBox = "[ ]"
		}
		rows[i+1][0] = fmt.Sprintf("%s %s", checkBox, m.inPlaceResult.Patches[pIdx].Pkg.Name)
	}
	// show select all only if nothing is selected,
	// show deselect all if anything is selected
	if anySelected {
		rows[0][0] = "DESELECT ALL"
	} else {
		rows[0][0] = "SELECT ALL"
	}
	st.table.SetRows(rows)
	// there is no table.Columns() method, so I can't resize the columns to fit the checkbox properly :(
}

func (st *stateChooseInPlacePatches) toggleSelection(idx int) {
	// TODO: Prevent selection of multiple (incompatible) patches for same package version
	i := st.patchIdx[idx]
	st.stateInPlace.selectedChanges[i] = !st.stateInPlace.selectedChanges[i]
}

func (st *stateChooseInPlacePatches) currentInfoView() (view tui.ViewModel, canFocus bool) {
	if c := st.table.Cursor(); c > 0 && c < len(st.table.Rows())-1 {
		return st.vulnsInfos[c-1], true
	}

	return emptyInfoView, false
}

func (st *stateChooseInPlacePatches) Resize(w, h int) {
	st.viewWidth = w
	st.table.SetWidth(w)
	st.table.SetHeight(h - 1) // -1 to account for 'Done' line at bottom
}

func (st *stateChooseInPlacePatches) ResizeInfo(w, h int) {
	for _, info := range st.vulnsInfos {
		info.Resize(w, h)
	}
}

func (st *stateChooseInPlacePatches) IsInfoFocused() bool {
	return st.focusedInfo != nil
}
