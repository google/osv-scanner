package fix

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
	lockf "github.com/google/osv-scanner/internal/resolution/lockfile"
	"github.com/google/osv-scanner/internal/tui"
	"golang.org/x/exp/slices"
)

type stateInPlaceResult struct {
	cursorPos int // TODO: use an enum
	canRelock bool

	selectedChanges []bool // in-place changes to be applied

	vulnList       tui.ViewModel
	inPlaceInfo    tui.ViewModel
	relockFixVulns tui.ViewModel

	focusedInfo tui.ViewModel // the infoview that is currently focused, nil if not focused
}

const (
	stateInPlaceFixed = iota
	stateInPlaceRemain
	stateInPlaceChoice
	stateInPlaceWrite
	stateInPlaceRelock
	stateInPlaceQuit
	stateInPlaceEnd
)

func (st *stateInPlaceResult) Init(m model) tea.Cmd {
	// pre-generate the info views for each option
	// inPlaceInfo is given to this by stateChooseStrategy when it makes this struct
	// Get the list of remaining vulns
	vulns := make([]*resolution.Vulnerability, len(m.inPlaceResult.Unfixable))
	for i := range m.inPlaceResult.Unfixable {
		vulns[i] = &m.inPlaceResult.Unfixable[i]
	}
	st.vulnList = tui.NewVulnList(vulns, "")

	// recompute the vulns fixed by relocking after the in-place update
	if m.options.Manifest != "" {
		st.canRelock = true
		var relockFixes []*resolution.Vulnerability
		for _, v := range vulns {
			if !slices.ContainsFunc(m.relockBaseRes.Vulns, func(r resolution.Vulnerability) bool {
				return r.OSV.ID == v.OSV.ID
			}) {
				relockFixes = append(relockFixes, v)
			}
		}
		st.relockFixVulns = tui.NewVulnList(relockFixes, "Relocking fixes the following vulns:")
	} else {
		st.canRelock = false
		st.relockFixVulns = infoStringView("Re-run with manifest to resolve vulnerabilities by re-locking")
	}

	st.cursorPos = stateInPlaceChoice
	st.ResizeInfo(m.infoViewWidth, m.infoViewHeight)

	return nil
}

func (st *stateInPlaceResult) Update(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case writeMsg: // just finished writing & installing the lockfile
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		m.writing = false
		// remove the written in-place changes
		var newPatches []remediation.InPlacePatch
		for i, selected := range st.selectedChanges {
			if !selected {
				newPatches = append(newPatches, m.inPlaceResult.Patches[i])
			}
		}
		m.inPlaceResult.Patches = newPatches
		// unselect all changes
		st.selectedChanges = make([]bool, len(newPatches))
		// regenerate the in-place info panel
		st.inPlaceInfo = tui.NewInPlaceInfo(*m.inPlaceResult)

		return m, cmd

	case tui.ViewModelCloseMsg:
		// info view wants to quit, just unfocus it
		st.focusedInfo = nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, tui.Keys.SwitchView):
			if st.IsInfoFocused() {
				st.focusedInfo = nil
			} else if view, canFocus := st.currentInfoView(); canFocus {
				st.focusedInfo = view
			}
		case st.IsInfoFocused():
			st.focusedInfo, cmd = st.focusedInfo.Update(msg)
		case key.Matches(msg, tui.Keys.Quit):
			// only quit if the cursor is over the quit line
			if st.cursorPos == stateInPlaceQuit {
				return m, tea.Quit
			}
			// move the cursor to the quit line if its not already there
			st.cursorPos = stateInPlaceQuit
		case key.Matches(msg, tui.Keys.Select):
			// enter key was pressed, parse input
			return st.parseInput(m)
		// move the cursor and show the corresponding info view
		case key.Matches(msg, tui.Keys.Up):
			if st.cursorPos > stateInPlaceFixed {
				st.cursorPos--
			}
		case key.Matches(msg, tui.Keys.Down):
			if st.cursorPos < stateInPlaceEnd-1 {
				st.cursorPos++
			}
		}
	}

	return m, cmd
}

func (st *stateInPlaceResult) currentInfoView() (view tui.ViewModel, canFocus bool) {
	switch st.cursorPos {
	case stateInPlaceFixed: // info - fixed vulns
		return st.inPlaceInfo, true
	case stateInPlaceRemain: // info - remaining vulns
		return st.vulnList, true
	case stateInPlaceChoice: // choose changes
		return infoStringView("Choose which changes to apply"), false
	case stateInPlaceWrite: // write
		return infoStringView("Write changes to lockfile"), false
	case stateInPlaceRelock: // relock
		return st.relockFixVulns, st.canRelock
	case stateInPlaceQuit: // quit
		return infoStringView("Exit Guided Remediation"), false
	default:
		return emptyInfoView, false
	}
}

func (st *stateInPlaceResult) parseInput(m model) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch st.cursorPos {
	case stateInPlaceFixed, stateInPlaceRemain: // info lines, focus info view
		v, _ := st.currentInfoView()
		st.focusedInfo = v
	case stateInPlaceChoice: // choose specific patches
		m.st = &stateChooseInPlacePatches{stateInPlace: st}
		cmd = m.st.Init(m)
	case stateInPlaceWrite: // write
		m.writing = true
		cmd = func() tea.Msg { return st.write(m) }
	case stateInPlaceRelock: // relock
		if st.canRelock {
			m.st = &stateRelockResult{}
			cmd = m.st.Init(m)
		}
	case stateInPlaceQuit: // quit
		cmd = tea.Quit
	}

	return m, cmd
}

func (st *stateInPlaceResult) View(m model) string {
	if m.writing {
		return ""
	}
	remainCount := len(m.inPlaceResult.Unfixable)
	fixCount := m.inPlaceResult.VulnCount().Total() - remainCount
	pkgCount := len(m.inPlaceResult.Patches)
	nSelected := 0
	for _, s := range st.selectedChanges {
		if s {
			nSelected++
		}
	}

	s := strings.Builder{}
	s.WriteString("IN-PLACE\n") // TODO: better page title/layout
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateInPlaceFixed,
		"",
		fmt.Sprintf("%%s can be changed, fixing %d vulnerabilities\n", fixCount),
		fmt.Sprintf("%d packages", pkgCount),
	))
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateInPlaceRemain,
		"",
		"%s remain\n",
		fmt.Sprintf("%d vulnerabilities", remainCount),
	))

	s.WriteString("\n")

	s.WriteString("Actions:\n")
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateInPlaceChoice,
		" > ",
		"%s which changes to apply\n",
		"Choose",
	))
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateInPlaceWrite,
		" > ",
		fmt.Sprintf("%%s %d changes to lockfile\n", nSelected),
		"Write",
	))
	if st.canRelock {
		s.WriteString(tui.RenderSelectorOption(
			st.cursorPos == stateInPlaceRelock,
			" > ",
			"%s the whole project instead\n",
			"Relock",
		))
	} else {
		s.WriteString(tui.RenderSelectorOption(
			st.cursorPos == stateInPlaceRelock,
			" > ",
			tui.DisabledTextStyle.Render("Cannot re-lock - missing manifest file\n"),
		))
	}
	s.WriteString("\n")
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateInPlaceQuit,
		"> ",
		"%s without saving changes\n",
		"quit",
	))

	return s.String()
}

func (st *stateInPlaceResult) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

func (st *stateInPlaceResult) Resize(_, _ int) {}

func (st *stateInPlaceResult) ResizeInfo(w, h int) {
	st.inPlaceInfo.Resize(w, h)
	st.vulnList.Resize(w, h)
	st.relockFixVulns.Resize(w, h)
}

func (st *stateInPlaceResult) IsInfoFocused() bool {
	return st.focusedInfo != nil
}

// TODO: Work out a better way to output npm commands
func (st *stateInPlaceResult) write(m model) tea.Msg {
	var changes []lockf.DependencyPatch
	for i, p := range m.inPlaceResult.Patches {
		if st.selectedChanges[i] {
			changes = append(changes, p.DependencyPatch)
		}
	}

	if err := lockf.Overwrite(m.options.LockfileRW, m.options.Lockfile, changes); err != nil {
		return writeMsg{err}
	}

	return writeMsg{nil}
}
