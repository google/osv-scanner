package fix

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scanner/internal/tui"
)

type stateInitialize struct {
	spinner spinner.Model // the loading spinner used to show progress
}

func (st *stateInitialize) Init(m model) tea.Cmd {
	// create the loading spinner
	st.spinner = tui.NewSpinner()
	cmds := []tea.Cmd{st.spinner.Tick}

	// TODO: both in-place/relock could potentially be done in parallel
	if m.options.Lockfile != "" {
		// if we have a lockfile, start calculating the in-place updates
		cmds = append(cmds, func() tea.Msg {
			return doInPlaceResolution(m.ctx, m.cl, m.options)
		})
	} else {
		// if we don't have a lockfile, start calculating the relock result
		cmds = append(cmds, func() tea.Msg {
			return doInitialRelock(m.ctx, m.options)
		})
	}

	return tea.Batch(cmds...)
}

func (st *stateInitialize) Update(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	// in-place resolution finished
	case inPlaceResolutionMsg:
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		// set the result and start the relock computation
		m.lockfileGraph = msg.g
		m.inPlaceResult = &msg.res
		if m.options.Manifest != "" {
			cmds = append(cmds, func() tea.Msg {
				return doInitialRelock(m.ctx, m.options)
			})
		} else {
			// TODO: skip choose strategy, go straight to in-place
			m.st = &stateChooseStrategy{}
			cmds = append(cmds, m.st.Init(m))
		}

	// relocking finished
	case doRelockMsg:
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		// set the result and go to next state
		m.relockBaseRes = msg.res
		m.relockBaseResErrs = m.relockBaseRes.Errors()
		if m.options.Lockfile == "" {
			m.st = &stateRelockResult{}
			cmds = append(cmds, m.st.Init(m))
		} else {
			m.st = &stateChooseStrategy{}
			cmds = append(cmds, m.st.Init(m))
		}
	}
	var c tea.Cmd
	st.spinner, c = st.spinner.Update(msg)
	cmds = append(cmds, c)

	return m, tea.Batch(cmds...)
}

func (st *stateInitialize) View(m model) string {
	s := strings.Builder{}
	if m.options.Lockfile == "" {
		s.WriteString("No lockfile provided. Assuming re-lock.\n")
	} else {
		s.WriteString(fmt.Sprintf("Scanning %s ", tui.SelectedTextStyle.Render(m.options.Lockfile)))
		if m.inPlaceResult == nil {
			s.WriteString(st.spinner.View())
			s.WriteString("\n")

			return s.String()
		}
		s.WriteString("✓\n")
	}

	s.WriteString(fmt.Sprintf("Resolving %s ", tui.SelectedTextStyle.Render(m.options.Manifest)))
	if m.relockBaseRes == nil {
		s.WriteString(st.spinner.View())
		s.WriteString("\n")
	} else {
		s.WriteString("✓\n")
	}
	// TODO: show non-fatal resolution errors somewhere

	return s.String()
}

func (st *stateInitialize) InfoView() string    { return "" }
func (st *stateInitialize) Resize(_, _ int)     {}
func (st *stateInitialize) ResizeInfo(_, _ int) {}
func (st *stateInitialize) IsInfoFocused() bool { return false }
