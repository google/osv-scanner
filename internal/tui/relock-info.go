package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/resolution"
)

// A ViewModel showing the dependency changes, the removed, and added vulnerabilities
// resulting from a proposed relock patch
type relockInfo struct {
	fixedHeight  float64
	fixedList    *vulnList
	addedList    *vulnList
	addedFocused bool
}

//revive:disable-next-line:unexported-return
func NewRelockInfo(change resolution.Difference) *relockInfo {
	info := relockInfo{fixedHeight: 1}
	preamble := strings.Builder{}
	preamble.WriteString("The following upgrades:\n")
	for _, dep := range change.Deps {
		preamble.WriteString(fmt.Sprintf("  %s@%s (%s) → @%s (%s)\n", // TODO: styling
			dep.Pkg.Name, dep.OrigRequire, dep.OrigResolved, dep.NewRequire, dep.NewResolved))
	}
	preamble.WriteString("Will resolve the following:")
	fixedVulns := make([]*resolution.Vulnerability, len(change.RemovedVulns))
	for i := range change.RemovedVulns {
		fixedVulns[i] = &change.RemovedVulns[i]
	}
	info.fixedList = NewVulnList(fixedVulns, preamble.String())

	if len(change.AddedVulns) == 0 {
		return &info
	}

	// Create a second list showing introduced vulns
	newVulns := make([]*resolution.Vulnerability, len(change.AddedVulns))
	for i := range change.AddedVulns {
		newVulns[i] = &change.AddedVulns[i]
	}
	info.addedList = NewVulnList(newVulns, "But will introduce the following new vulns:")
	info.addedList.Blur()

	// divide two lists by roughly how many lines each would have
	const fixedMinHeight = 0.5
	const fixedMaxHeight = 0.8
	fixed := float64(len(change.Deps) + len(fixedVulns))
	added := float64(len(newVulns))
	info.fixedHeight = fixed / (fixed + added)
	if info.fixedHeight < fixedMinHeight {
		info.fixedHeight = fixedMinHeight
	}
	if info.fixedHeight > fixedMaxHeight {
		info.fixedHeight = fixedMaxHeight
	}

	return &info
}

func (r *relockInfo) Resize(w, h int) {
	fixedHeight := int(r.fixedHeight * float64(h))
	r.fixedList.Resize(w, fixedHeight)
	if r.addedList != nil {
		r.addedList.Resize(w, h-fixedHeight)
	}
}

func (r *relockInfo) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	var cmds []tea.Cmd

	// check if we're trying to scroll past the end of one of the lists
	if msg, ok := msg.(tea.KeyMsg); ok && r.addedList != nil {
		// scrolling up out of the added list
		if r.addedFocused &&
			r.addedList.Index() == 0 &&
			key.Matches(msg, Keys.Up) {
			r.addedFocused = false
			r.addedList.Blur()
			r.fixedList.Focus()

			return r, nil
		}
		// scrolling down out of fixed list
		if !r.addedFocused &&
			r.fixedList.Index() == len(r.fixedList.Items())-1 &&
			key.Matches(msg, Keys.Down) {
			r.addedFocused = true
			r.addedList.Focus()
			r.fixedList.Blur()

			return r, nil
		}
	}

	// do normal updates
	l, cmd := r.fixedList.Update(msg)
	r.fixedList = l.(*vulnList)
	cmds = append(cmds, cmd)

	if r.addedList != nil {
		l, cmd := r.addedList.Update(msg)
		r.addedList = l.(*vulnList)
		cmds = append(cmds, cmd)
	}

	return r, tea.Batch(cmds...)
}

func (r *relockInfo) View() string {
	if r.addedList == nil || r.fixedList.currVulnInfo != nil {
		return r.fixedList.View()
	}
	if r.addedList.currVulnInfo != nil {
		return r.addedList.View()
	}

	return lipgloss.JoinVertical(lipgloss.Center, r.fixedList.View(), r.addedList.View())
}
