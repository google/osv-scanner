package fix

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	manif "github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/tui"
	"golang.org/x/exp/maps"
)

type stateRelockResult struct {
	currRes      *resolution.Result      // In-progress relock result, with user-selected patches applied
	currErrs     []resolution.NodeError  // In-progress relock errors
	patches      []resolution.Difference // current possible patches applicable to relockCurrRes
	patchesDone  bool                    // whether the relockPatches has finished being computed
	numUnfixable int                     // count of unfixable vulns, for rendering

	spinner         spinner.Model
	cursorPos       int              // TODO: use an enum ?
	selectedPatches map[int]struct{} // currently pending selected patches
	viewWidth       int              // width for rendering (same as model.mainViewWidth)

	vulnList      tui.ViewModel
	unfixableList tui.ViewModel
	patchInfo     []tui.ViewModel
	resolveErrors tui.ViewModel

	focusedInfo tui.ViewModel // the infoview that is currently focused, nil if not focused
}

const (
	stateRelockRemain = iota
	stateRelockUnfixable
	stateRelockErrors
	stateRelockPatches
	stateRelockApply
	stateRelockWrite
	stateRelockQuit
	stateRelockEnd
)

// gets the cursor position, accounting for the arbitrary number of relockPatches
// returns stateRelockPatches if over ANY of the relockPatches
func (st *stateRelockResult) getEffectiveCursor() int {
	if st.cursorPos < stateRelockPatches {
		return st.cursorPos
	}

	if len(st.patches) == 0 {
		// skip over stateRelockPatches and stateRelockApply
		return st.cursorPos + 2
	}

	if st.cursorPos < stateRelockPatches+len(st.patches) {
		return stateRelockPatches
	}

	return st.cursorPos - len(st.patches) + 1
}

// sets the cursor to the effective position, accounting for the arbitrary number of relockPatches
// setting to stateRelockPatches will go to first patch
func (st *stateRelockResult) setEffectiveCursor(pos int) {
	switch {
	case pos <= stateRelockPatches:
		st.cursorPos = pos
	case len(st.patches) == 0:
		st.cursorPos = pos - 2
	default:
		st.cursorPos = pos + len(st.patches) - 1
	}
}

// get the index of the patch the cursor is currently over
func (st *stateRelockResult) getPatchIndex() int {
	return st.cursorPos - stateRelockPatches
}

func (st *stateRelockResult) Init(m model) tea.Cmd {
	st.currRes = m.relockBaseRes
	st.currErrs = m.relockBaseResErrs
	st.resolveErrors = resolutionErrorView(st.currRes, st.currErrs)
	st.patchesDone = false
	st.spinner = tui.NewSpinner()
	st.cursorPos = -1
	st.selectedPatches = make(map[int]struct{})
	st.viewWidth = m.mainViewWidth

	// Make the vulnerability list view model
	vulns := make([]*resolution.Vulnerability, len(st.currRes.Vulns))
	for i := range st.currRes.Vulns {
		vulns[i] = &st.currRes.Vulns[i]
	}
	st.vulnList = tui.NewVulnList(vulns, "")
	st.ResizeInfo(m.infoViewWidth, m.infoViewHeight)

	return tea.Batch(
		func() tea.Msg {
			return doComputeRelockPatches(m.ctx, m.cl, st.currRes, m.options)
		}, // start computing possible patches
		st.spinner.Tick, // spin the spinner
	)
}

func (st *stateRelockResult) Update(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case doRelockMsg: // finished resolving (after selecting multiple patches)
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		st.currRes = msg.res
		// recreate the vuln list info view
		var vulns []*resolution.Vulnerability
		for i := range st.currRes.Vulns {
			vulns = append(vulns, &st.currRes.Vulns[i])
		}
		st.vulnList = tui.NewVulnList(vulns, "")
		st.currErrs = st.currRes.Errors()
		st.resolveErrors = resolutionErrorView(st.currRes, st.currErrs)
		// Compute possible patches again
		st.patchesDone = false
		cmd = func() tea.Msg {
			return doComputeRelockPatches(m.ctx, m.cl, st.currRes, m.options)
		}
	case relockPatchMsg: // patch computation done
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		st.patches = msg.patches
		maps.Clear(st.selectedPatches)
		st.buildPatchInfoViews(m)
		st.patchesDone = true
		if len(st.patches) > 0 {
			// place the cursor on the first patch
			st.setEffectiveCursor(stateRelockPatches)
		} else {
			// no patches, place the cursor on the 'write' line
			st.setEffectiveCursor(stateRelockWrite)
		}

	case writeMsg: // just finished writing & installing the manifest
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		m.writing = false
		m.relockBaseRes = st.currRes // relockBaseRes must match what is in the package.json
		m.relockBaseResErrs = m.relockBaseRes.Errors()
		maps.Clear(st.selectedPatches)

	case tui.ViewModelCloseMsg:
		// info view wants to quit, just unfocus it
		st.focusedInfo = nil
	case tea.KeyMsg:
		if !st.patchesDone { // Don't accept input in the middle of computation
			return m, nil
		}
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
			if st.getEffectiveCursor() == stateRelockQuit {
				return m, tea.Quit
			}
			// move the cursor to the quit line if its not already there
			st.setEffectiveCursor(stateRelockQuit)
		case key.Matches(msg, tui.Keys.Select): // enter key pressed
			return st.parseInput(m)
		// move the cursor
		case key.Matches(msg, tui.Keys.Up):
			if st.getEffectiveCursor() > stateRelockRemain {
				st.cursorPos--
				if st.getEffectiveCursor() == stateRelockErrors && len(st.currErrs) == 0 {
					st.cursorPos--
				}
			}
		case key.Matches(msg, tui.Keys.Down):
			if st.getEffectiveCursor() < stateRelockEnd-1 {
				st.cursorPos++
				if st.getEffectiveCursor() == stateRelockErrors && len(st.currErrs) == 0 {
					st.cursorPos++
				}
			}
		}
	}
	var c tea.Cmd
	st.spinner, c = st.spinner.Update(msg)

	return m, tea.Batch(cmd, c)
}

func (st *stateRelockResult) currentInfoView() (view tui.ViewModel, canFocus bool) {
	switch st.getEffectiveCursor() {
	case stateRelockRemain: // remaining vulns
		return st.vulnList, true
	case stateRelockUnfixable: // unfixable vulns
		return st.unfixableList, true
	case stateRelockErrors:
		return st.resolveErrors, false
	case stateRelockPatches: // one of the patches
		return st.patchInfo[st.getPatchIndex()], true
	case stateRelockApply:
		return infoStringView("Apply the selected patches and recompute vulnerabilities"), false
	case stateRelockWrite:
		return infoStringView("Shell out to write manifest & lockfile"), false
	case stateRelockQuit:
		return infoStringView("Exit Guided Remediation"), false
	default:
		return emptyInfoView, false // invalid (panic?)
	}
}

func (st *stateRelockResult) buildPatchInfoViews(m model) {
	// create the info view for each of the patches
	// and the unfixable vulns
	st.patchInfo = nil
	for _, p := range st.patches {
		st.patchInfo = append(st.patchInfo, tui.NewRelockInfo(p))
	}

	unfixableVulns := relockUnfixableVulns(st.patches)
	st.unfixableList = tui.NewVulnList(unfixableVulns, "")
	st.numUnfixable = len(unfixableVulns)
	st.ResizeInfo(m.infoViewWidth, m.infoViewHeight)
}

func (st *stateRelockResult) parseInput(m model) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch st.getEffectiveCursor() {
	case stateRelockRemain: // vuln line, focus info view
		st.focusedInfo = st.vulnList
	case stateRelockUnfixable: // unfixable vulns line, focus info ciew
		st.focusedInfo = st.unfixableList
	case stateRelockPatches: // patch selected
		idx := st.getPatchIndex()
		if _, ok := st.selectedPatches[idx]; ok { // if already selected, deselect it
			delete(st.selectedPatches, idx)
		} else if st.patchCompatible(idx) { // if it's compatible with current other selections, select it
			st.selectedPatches[idx] = struct{}{}
		}
	case stateRelockApply: // apply changes
		if len(st.selectedPatches) > 0 {
			m, cmd = st.relaxChoice(m)
		}
	case stateRelockWrite: // write
		m.writing = true
		cmd = func() tea.Msg { return st.write(m) }
	case stateRelockQuit: // quit
		cmd = tea.Quit
	}

	return m, cmd
}

func (st *stateRelockResult) relaxChoice(m model) (model, tea.Cmd) {
	if len(st.selectedPatches) == 1 {
		// If it's just a single patch, we've already computed the relock result
		for i := range st.selectedPatches { // selectedPatches is a map, iterate for the single key
			st.currRes = st.patches[i].New
			st.currErrs = st.currRes.Errors()
			st.resolveErrors = resolutionErrorView(st.currRes, st.currErrs)
			// recreate vuln list view
			var vulns []*resolution.Vulnerability
			for i := range st.currRes.Vulns {
				vulns = append(vulns, &st.currRes.Vulns[i])
			}
			st.vulnList = tui.NewVulnList(vulns, "")
			// Need to compute the possible patches from here
			return m, func() tea.Msg {
				return doComputeRelockPatches(m.ctx, m.cl, st.currRes, m.options)
			}
		}
	}

	// Compute combined changes and re-resolve the graph
	manifest := st.currRes.Manifest.Clone()
	for i := range st.selectedPatches {
		for _, dp := range st.patches[i].Deps {
			for idx := range manifest.Requirements {
				rv := manifest.Requirements[idx]
				if rv.Name == dp.Pkg.Name && rv.Version == dp.OrigRequire {
					rv.Version = dp.NewRequire
					manifest.Requirements[idx] = rv
				}
			}
		}
	}

	st.currRes = nil

	return m, func() tea.Msg {
		return doRelock(m.ctx, m.cl, manifest, m.options.ResolveOpts, m.options.MatchVuln)
	}
}

func (st *stateRelockResult) View(m model) string {
	if m.writing {
		return ""
	}
	s := strings.Builder{}
	s.WriteString("RELOCK\n")
	if st.currRes == nil {
		s.WriteString("Resolving dependency graph ")
		s.WriteString(st.spinner.View())
		s.WriteString("\n")

		return s.String()
	}

	s.WriteString(tui.RenderSelectorOption(
		st.getEffectiveCursor() == stateRelockRemain,
		"",
		"%s remain\n",
		fmt.Sprintf("%d vulnerabilities", len(st.currRes.Vulns)),
	))

	// TODO: Show current staged changes

	if !st.patchesDone {
		s.WriteString("\n")
		s.WriteString("Computing possible patches ")
		s.WriteString(st.spinner.View())
		s.WriteString("\n")

		return s.String()
	}

	s.WriteString(tui.RenderSelectorOption(
		st.getEffectiveCursor() == stateRelockUnfixable,
		"",
		"%s are unfixable\n",
		fmt.Sprintf("%d vulnerabilities", st.numUnfixable),
	))

	if len(st.currErrs) > 0 {
		s.WriteString(tui.RenderSelectorOption(
			st.cursorPos == stateRelockErrors,
			"",
			"WARNING: Encountered %s during graph resolution.\n",
			fmt.Sprintf("%d errors", len(st.currErrs)),
		))
	}
	s.WriteString("\n")

	if len(st.patches) == 0 {
		s.WriteString("No remaining vulnerabilities can be fixed.\n")
	} else {
		s.WriteString("Actions:\n")
		patchStrs := make([]string, len(st.patches))
		for i, patch := range st.patches {
			var checkBox string
			if _, ok := st.selectedPatches[i]; ok {
				checkBox = "[x]"
			} else {
				checkBox = "[ ]"
			}
			if !st.patchCompatible(i) {
				checkBox = tui.DisabledTextStyle.Render(checkBox)
			}
			checkBox = tui.RenderSelectorOption(
				st.cursorPos == stateRelockPatches+i,
				" > ",
				"%s ",
				checkBox,
			)
			text := diffString(patch)
			var textSt lipgloss.Style
			if st.patchCompatible(i) {
				textSt = lipgloss.NewStyle()
			} else {
				textSt = tui.DisabledTextStyle
			}
			text = textSt.Width(st.viewWidth - lipgloss.Width(checkBox)).Render(text)
			patchStrs[i] = lipgloss.JoinHorizontal(lipgloss.Top, checkBox, text)
		}
		s.WriteString(lipgloss.JoinVertical(lipgloss.Left, patchStrs...))
		s.WriteString("\n")

		if len(st.selectedPatches) > 0 {
			s.WriteString(tui.RenderSelectorOption(
				st.getEffectiveCursor() == stateRelockApply,
				"> ",
				"%s pending patches\n",
				"Apply",
			))
		} else {
			s.WriteString(tui.RenderSelectorOption(
				st.getEffectiveCursor() == stateRelockApply,
				"> ",
				tui.DisabledTextStyle.Render("No pending patches")+"\n",
			))
		}
	}

	s.WriteString(tui.RenderSelectorOption(
		st.getEffectiveCursor() == stateRelockWrite,
		"> ",
		"%s changes to manifest\n",
		"Write",
	))
	s.WriteString("\n")
	s.WriteString(tui.RenderSelectorOption(
		st.getEffectiveCursor() == stateRelockQuit,
		"> ",
		"%s without saving changes\n",
		"quit",
	))

	return s.String()
}

func diffString(diff resolution.Difference) string {
	var depStr string
	if len(diff.Deps) == 1 {
		dep := diff.Deps[0]
		depStr = fmt.Sprintf("%s@%s → @%s", dep.Pkg.Name, dep.OrigRequire, dep.NewRequire)
	} else {
		depStr = fmt.Sprintf("%d packages", len(diff.Deps))
	}
	str := fmt.Sprintf("Upgrading %s resolves %d vulns", depStr, len(diff.RemovedVulns))
	if len(diff.AddedVulns) > 0 {
		str += fmt.Sprintf(" but introduces %d new vulns", len(diff.AddedVulns))
	}

	return str
}

func (st *stateRelockResult) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

// check if a patch is compatible with the currently selected patches
// i.e. if none of the direct dependencies in the current patch appear in the already selected patches
func (st *stateRelockResult) patchCompatible(idx int) bool {
	if _, ok := st.selectedPatches[idx]; ok {
		// already selected, it must be compatible
		return true
	}
	// find any shared direct dependency packages
	patch := st.patches[idx]
	for i := range st.selectedPatches {
		curr := st.patches[i]
		for _, dep := range curr.Deps {
			for _, newDep := range patch.Deps {
				if dep.Pkg == newDep.Pkg {
					return false
				}
			}
		}
	}

	return true
}

func (st *stateRelockResult) Resize(w, _ int) {
	st.viewWidth = w
}

func (st *stateRelockResult) ResizeInfo(w, h int) {
	st.vulnList.Resize(w, h)
	for _, info := range st.patchInfo {
		info.Resize(w, h)
	}
}

func (st *stateRelockResult) IsInfoFocused() bool {
	return st.focusedInfo != nil
}

// TODO: Work out a better way to output npm commands
func (st *stateRelockResult) write(m model) tea.Msg {
	changes := m.relockBaseRes.CalculateDiff(st.currRes)
	if err := manif.Overwrite(m.options.ManifestRW, m.options.Manifest, changes.Patch); err != nil {
		return writeMsg{err}
	}

	if m.options.Lockfile == "" && m.options.RelockCmd == "" {
		// TODO: there's no user feedback to show this was successful
		return writeMsg{nil}
	}

	c, err := regenerateLockfileCmd(m.options)
	if err != nil {
		return writeMsg{err}
	}

	return tea.ExecProcess(c, func(err error) tea.Msg {
		if err != nil && m.options.RelockCmd == "" {
			// try again with "--legacy-peer-deps"
			c, err := regenerateLockfileCmd(m.options)
			if err != nil {
				return writeMsg{err}
			}
			c.Args = append(c.Args, "--legacy-peer-deps")

			return tea.ExecProcess(c, func(err error) tea.Msg { return writeMsg{err} })()
		}

		return writeMsg{err}
	})()
}

type relockPatchMsg struct {
	patches []resolution.Difference
	err     error
}

// Find all groups of dependency bumps required to resolve each vulnerability individually
func doComputeRelockPatches(ctx context.Context, cl client.ResolutionClient, currRes *resolution.Result, opts osvFixOptions) relockPatchMsg {
	patches, err := remediation.ComputeRelaxPatches(ctx, cl, currRes, opts.Options)
	if err != nil {
		return relockPatchMsg{err: err}
	}

	return relockPatchMsg{patches: patches}
}
