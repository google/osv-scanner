package fix

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/tui"
	"golang.org/x/exp/slices"
)

type stateChooseStrategy struct {
	cursorPos int // TODO: use an enum
	canRelock bool

	vulnList       tui.ViewModel
	inPlaceInfo    tui.ViewModel
	relockFixVulns tui.ViewModel
	errorsView     tui.ViewModel

	depthInput    textinput.Model
	severityInput textinput.Model

	focusedInfo tui.ViewModel // the infoview that is currently focused, nil if not focused
}

const (
	stateChooseInfo = iota
	stateChooseErrors
	stateChooseInPlace
	stateChooseRelock
	stateChooseDepth
	stateChooseSeverity
	stateChooseDev
	stateChooseApplyCriteria
	stateChooseQuit
	stateChooseEnd
)

func (st *stateChooseStrategy) Init(m model) tea.Cmd {
	st.cursorPos = stateChooseInPlace
	// pre-generate the info views for each option

	// make a slice of vuln pointers for the all vulnerabilities list
	// TODO: be consistent & efficient with how we pass resolution.Vulnerabilities around
	var allVulns []*resolution.Vulnerability //nolint:prealloc // it's a bit annoying to count beforehand
	for _, p := range m.inPlaceResult.Patches {
		for i := range p.ResolvedVulns {
			allVulns = append(allVulns, &p.ResolvedVulns[i])
		}
	}
	for i := range m.inPlaceResult.Unfixable {
		allVulns = append(allVulns, &m.inPlaceResult.Unfixable[i])
	}
	st.vulnList = tui.NewVulnList(allVulns, "")

	// make the in-place view
	st.inPlaceInfo = tui.NewInPlaceInfo(*m.inPlaceResult)

	if m.options.Manifest != "" {
		// find the vulns fixed by relocking to show on the relock hover
		st.canRelock = true
		var relockFixes []*resolution.Vulnerability
		for _, v := range allVulns {
			if !slices.ContainsFunc(m.relockBaseRes.Vulns, func(r resolution.Vulnerability) bool {
				return r.OSV.ID == v.OSV.ID
			}) {
				relockFixes = append(relockFixes, v)
			}
		}
		st.relockFixVulns = tui.NewVulnList(relockFixes, "Relocking fixes the following vulns:")
		st.ResizeInfo(m.infoViewWidth, m.infoViewHeight)
	} else {
		st.canRelock = false
		st.relockFixVulns = infoStringView("Re-run with manifest to resolve vulnerabilities by re-locking")
	}

	st.depthInput = textinput.New()
	st.depthInput.CharLimit = 3
	st.depthInput.SetValue(strconv.Itoa(m.options.MaxDepth))

	st.severityInput = textinput.New()
	st.severityInput.CharLimit = 4
	st.severityInput.SetValue(strconv.FormatFloat(m.options.MinSeverity, 'g', -1, 64))

	st.errorsView = resolutionErrorView(m.relockBaseRes, m.relockBaseResErrs)

	return nil
}

func (st *stateChooseStrategy) Update(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
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
			var cmd tea.Cmd
			st.focusedInfo, cmd = st.focusedInfo.Update(msg)

			return m, cmd
		case key.Matches(msg, tui.Keys.Quit):
			// only quit if the cursor is over the quit line
			if st.cursorPos == stateChooseQuit {
				return m, tea.Quit
			}
			// otherwise move the cursor to the quit line if its not already there
			st.cursorPos = stateChooseQuit
		case key.Matches(msg, tui.Keys.Select):
			// enter key was pressed, parse input
			return st.parseInput(m)
		// move the cursor and show the corresponding info view
		case key.Matches(msg, tui.Keys.Up):
			if st.cursorPos > stateChooseInfo {
				st.cursorPos--
				// Resolution errors aren't rendered if there are none
				if st.cursorPos == stateChooseErrors && len(m.relockBaseResErrs) == 0 {
					st.cursorPos--
				}
			}
			st.UpdateTextFocus()
		case key.Matches(msg, tui.Keys.Down):
			if st.cursorPos < stateChooseEnd-1 {
				st.cursorPos++
				if st.cursorPos == stateChooseErrors && len(m.relockBaseResErrs) == 0 {
					st.cursorPos++
				}
			}
			st.UpdateTextFocus()
		}
	}

	var cmd tea.Cmd
	st.depthInput, cmd = st.depthInput.Update(msg)
	cmds = append(cmds, cmd)

	st.severityInput, cmd = st.severityInput.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (st *stateChooseStrategy) UpdateTextFocus() {
	st.depthInput.Blur()
	st.severityInput.Blur()

	switch st.cursorPos {
	case stateChooseDepth:
		st.depthInput.Focus()
	case stateChooseSeverity:
		st.severityInput.Focus()
	}
}

func (st *stateChooseStrategy) IsInfoFocused() bool {
	return st.focusedInfo != nil
}

func (st *stateChooseStrategy) currentInfoView() (view tui.ViewModel, canFocus bool) {
	switch st.cursorPos {
	case stateChooseInfo: // info line
		return st.vulnList, true
	case stateChooseErrors:
		return st.errorsView, false
	case stateChooseInPlace: // in-place
		return st.inPlaceInfo, true
	case stateChooseRelock: // relock
		return st.relockFixVulns, st.canRelock
	case stateChooseQuit: // quit
		return infoStringView("Exit Guided Remediation"), false
	default:
		return emptyInfoView, false
	}
}

func (st *stateChooseStrategy) parseInput(m model) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch st.cursorPos {
	case stateChooseInfo: // info line, focus on info view
		st.focusedInfo = st.vulnList
	case stateChooseInPlace: // in-place
		// initially have every change be selected to be applied
		selected := make([]bool, len(m.inPlaceResult.Patches))
		for i := range selected {
			selected[i] = true
		}
		m.st = &stateInPlaceResult{inPlaceInfo: st.inPlaceInfo, selectedChanges: selected}
		cmd = m.st.Init(m)
	case stateChooseRelock: // relock
		if st.canRelock {
			m.st = &stateRelockResult{}
			cmd = m.st.Init(m)
		}
	case stateChooseDev:
		m.options.DevDeps = !m.options.DevDeps
	case stateChooseApplyCriteria:
		maxDepth, err := strconv.Atoi(st.depthInput.Value())
		if err == nil {
			m.options.MaxDepth = maxDepth
		}

		minSeverity, err := strconv.ParseFloat(st.severityInput.Value(), 64)
		if err == nil {
			m.options.MinSeverity = minSeverity
		}

		// Reset state. TODO: Add a spinner and do this I/O as a command.
		res, err := remediation.ComputeInPlacePatches(m.ctx, m.cl, m.lockfileGraph, m.options.Options)
		if err != nil {
			panic(err)
		}
		m.inPlaceResult = &res

		m.relockBaseRes.FilterVulns(m.options.MatchVuln)

		m.st = &stateChooseStrategy{}
		cmd = m.st.Init(m)
	case stateChooseQuit: // quit line
		cmd = tea.Quit
	}

	return m, cmd
}

func (st *stateChooseStrategy) View(m model) string {
	vulnCount := m.inPlaceResult.VulnCount()
	fixCount := vulnCount.Total() - len(m.inPlaceResult.Unfixable)
	pkgChange := len(m.inPlaceResult.Patches)

	s := strings.Builder{}
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseInfo,
		"",
		fmt.Sprintf("Found %%s in lockfile (%d direct, %d transitive, %d dev only) matching the criteria.\n", vulnCount.Direct, vulnCount.Transitive, vulnCount.Dev),
		fmt.Sprintf("%d vulnerabilities", vulnCount.Total()),
	))
	if len(m.relockBaseResErrs) > 0 {
		s.WriteString(tui.RenderSelectorOption(
			st.cursorPos == stateChooseErrors,
			"",
			"WARNING: Encountered %s during graph resolution.\n",
			fmt.Sprintf("%d errors", len(m.relockBaseResErrs)),
		))
	}
	s.WriteString("\n")
	s.WriteString("Actions:\n")
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseInPlace,
		" > ",
		fmt.Sprintf("%%s (fixes %d/%d vulns, changes %d packages)\n", fixCount, vulnCount.Total(), pkgChange),
		"Modify lockfile in-place",
	))

	// TODO: skip choseStrategy when relocking is unavailable
	if st.canRelock {
		// TODO: In-place and relock count vulns differently; this number is wrong
		relockFix := vulnCount.Total() - len(m.relockBaseRes.Vulns)
		s.WriteString(tui.RenderSelectorOption(
			st.cursorPos == stateChooseRelock,
			" > ",
			fmt.Sprintf("%%s (fixes %d/%d vulns) and try direct dependency upgrades\n", relockFix, vulnCount.Total()),
			"Re-lock project",
		))
	} else {
		s.WriteString(tui.RenderSelectorOption(
			st.cursorPos == stateChooseRelock,
			" > ",
			tui.DisabledTextStyle.Render("Cannot re-lock - missing manifest file\n"),
		))
	}
	s.WriteString("\n")
	s.WriteString("Criteria:\n")
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseDepth,
		" > ",
		fmt.Sprintf("%%s: %s\n", st.depthInput.View()),
		"Max dependency depth",
	))
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseSeverity,
		" > ",
		fmt.Sprintf("%%s: %s\n", st.severityInput.View()),
		"Min CVSS score",
	))

	devString := "YES"
	if m.options.DevDeps {
		devString = "NO"
	}
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseDev,
		" > ",
		fmt.Sprintf("%%s: %s\n", devString),
		"Exclude dev only",
	))
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseApplyCriteria,
		" > ",
		"%s\n",
		"Apply criteria",
	))

	s.WriteString("\n")
	s.WriteString(tui.RenderSelectorOption(
		st.cursorPos == stateChooseQuit,
		"> ",
		"%s\n",
		"quit",
	))

	return s.String()
}

func (st *stateChooseStrategy) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

func (st *stateChooseStrategy) Resize(_, _ int) {}

func (st *stateChooseStrategy) ResizeInfo(w, h int) {
	st.vulnList.Resize(w, h)
	st.inPlaceInfo.Resize(w, h)
	st.relockFixVulns.Resize(w, h)
}
