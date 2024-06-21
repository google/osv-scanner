package fix

import (
	"context"
	"os"
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scanner/internal/remediation"
	"github.com/google/osv-scanner/internal/resolution"
	"github.com/google/osv-scanner/internal/resolution/client"
	manif "github.com/google/osv-scanner/internal/resolution/manifest"
	"github.com/google/osv-scanner/internal/tui"
	osvLockfile "github.com/google/osv-scanner/pkg/lockfile"
	"golang.org/x/term"
)

type model struct {
	//nolint:containedctx
	ctx           context.Context         // Context, mostly used in deps.dev functions
	options       osvFixOptions           // options, from command line
	cl            client.ResolutionClient // graph client used for deps.dev functions
	lockfileGraph *resolve.Graph

	termWidth  int // width of the whole terminal
	termHeight int // height of the whole terminal

	mainViewWidth  int            // width of the main view
	mainViewHeight int            // height of the main view
	mainViewStyle  lipgloss.Style // border style to render the main view

	infoViewWidth  int            // width of the secondary info view
	infoViewHeight int            // height of the info view
	infoViewStyle  lipgloss.Style // border style to render the info view

	help help.Model // help text renderer

	st      modelState // current state of program
	err     error      // set if a fatal error occurs within the program
	writing bool       // whether the model is currently shelling out writing lockfile/manifest file

	inPlaceResult     *remediation.InPlaceResult   // results & patches from minimal / in-place resolution
	relockBaseRes     *resolution.ResolutionResult // Base relock result, matching the current manifest on disk
	relockBaseResErrs []resolution.ResolutionError // Errors in base relock result
}

func newModel(ctx context.Context, opts osvFixOptions, cl client.ResolutionClient) model {
	mainViewStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		Padding(tui.ViewVPad, tui.ViewHPad)

	infoViewStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		Padding(tui.ViewVPad, tui.ViewHPad)

	m := model{
		ctx:           ctx,
		options:       opts,
		cl:            cl,
		st:            &stateInitialize{},
		mainViewStyle: mainViewStyle,
		infoViewStyle: infoViewStyle,
		help:          help.New(),
	}
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		panic(err)
	}
	m.setTermSize(w, h)

	return m
}

func (m *model) setTermSize(w, h int) {
	m.termWidth = w
	m.termHeight = h

	// The internal rendering space of the views occupy a percentage of the terminal width
	viewWidth := int(float64(w) * tui.ViewWidthPct)
	if viewWidth < tui.ViewMinWidth {
		viewWidth = tui.ViewMinWidth
	}
	// The internal height is constant
	viewHeight := tui.ViewMinHeight

	// The total width/height, including the whitespace padding and border characters on each side
	paddedWidth := viewWidth + 2*tui.ViewHPad + 2
	paddedHeight := viewHeight + 2*tui.ViewVPad + 2

	// resize the views to the calculated dimensions
	m.mainViewWidth = viewWidth
	m.mainViewHeight = viewHeight
	m.mainViewStyle = m.mainViewStyle.Width(paddedWidth).Height(paddedHeight)

	m.infoViewWidth = viewWidth
	m.infoViewHeight = viewHeight
	m.infoViewStyle = m.infoViewStyle.Width(paddedWidth).Height(paddedHeight)

	m.st.Resize(m.mainViewWidth, m.mainViewHeight)
	m.st.ResizeInfo(m.infoViewWidth, m.infoViewHeight)
}

func (m *model) getBorderStyles() (lipgloss.Style, lipgloss.Style) {
	if m.st.IsInfoFocused() {
		m.infoViewStyle = m.infoViewStyle.UnsetBorderForeground()
		m.mainViewStyle = m.mainViewStyle.BorderForeground(tui.ColorDisabled)
	} else {
		m.infoViewStyle = m.infoViewStyle.BorderForeground(tui.ColorDisabled)
		m.mainViewStyle = m.mainViewStyle.UnsetBorderForeground()
	}

	return m.mainViewStyle, m.infoViewStyle
}

// TODO: Handle all errors better, instead of just quitting on any error
func errorAndExit(m model, err error) (tea.Model, tea.Cmd) {
	m.err = err
	return m, tea.Quit
}

func (m model) Init() tea.Cmd {
	return m.st.Init(m)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case msg.Type == tea.KeyCtrlC: // always quit on ctrl+c
			return m, tea.Quit
		case key.Matches(msg, tui.Keys.Help): // toggle help
			m.help.ShowAll = !m.help.ShowAll
		}
	case tea.WindowSizeMsg:
		m.setTermSize(msg.Width, msg.Height)
	}

	return m.st.Update(m, msg)
}

func (m model) View() string {
	// render both views side-by-side
	mainStyle, infoStyle := m.getBorderStyles()
	mainView := mainStyle.Render(m.st.View(m))
	infoView := infoStyle.Render(m.st.InfoView())
	view := lipgloss.JoinHorizontal(lipgloss.Top, mainView, infoView)

	// If we can't fit both side-by-side, only render the focused view
	if lipgloss.Width(view) > m.termWidth {
		if m.st.IsInfoFocused() {
			view = infoView
		} else {
			view = mainView
		}
	}

	// add the help to the bottom
	view = lipgloss.JoinVertical(lipgloss.Center, view, m.help.View(tui.Keys))

	return lipgloss.Place(m.termWidth, m.termHeight, lipgloss.Center, lipgloss.Center, view)
}

type modelState interface {
	Init(m model) tea.Cmd
	Update(m model, msg tea.Msg) (tea.Model, tea.Cmd)
	View(m model) string
	Resize(w, h int)

	InfoView() string
	ResizeInfo(w, h int)
	IsInfoFocused() bool
}

type inPlaceResolutionMsg struct {
	res remediation.InPlaceResult
	g   *resolve.Graph
	err error
}

func doInPlaceResolution(ctx context.Context, cl client.ResolutionClient, opts osvFixOptions) tea.Msg {
	lf, err := osvLockfile.OpenLocalDepFile(opts.Lockfile)
	if err != nil {
		return inPlaceResolutionMsg{err: err}
	}
	defer lf.Close()
	g, err := opts.LockfileRW.Read(lf)
	if err != nil {
		return inPlaceResolutionMsg{err: err}
	}
	res, err := remediation.ComputeInPlacePatches(ctx, cl, g, opts.RemediationOptions)

	return inPlaceResolutionMsg{res, g, err}
}

type doRelockMsg struct {
	res *resolution.ResolutionResult
	err error
}

func doRelock(ctx context.Context, cl client.ResolutionClient, m manif.Manifest, matchFn func(resolution.ResolutionVuln) bool) tea.Msg {
	res, err := resolution.Resolve(ctx, cl, m)
	if err != nil {
		return doRelockMsg{nil, err}
	}

	if err := cl.WriteCache(m.FilePath); err != nil {
		return doRelockMsg{nil, err}
	}

	res.FilterVulns(matchFn)

	return doRelockMsg{res, nil}
}

func doInitialRelock(ctx context.Context, opts osvFixOptions) tea.Msg {
	f, err := osvLockfile.OpenLocalDepFile(opts.Manifest)
	if err != nil {
		return doRelockMsg{err: err}
	}
	defer f.Close()
	m, err := opts.ManifestRW.Read(f)
	if err != nil {
		return doRelockMsg{err: err}
	}
	opts.Client.PreFetch(ctx, m.Requirements, m.FilePath)

	return doRelock(ctx, opts.Client, m, opts.MatchVuln)
}

// tui.ViewModel for showing non-interactive strings
type infoStringView string

func (s infoStringView) Update(tea.Msg) (tui.ViewModel, tea.Cmd) { return s, nil }
func (s infoStringView) View() string                            { return string(s) }
func (s infoStringView) Resize(int, int)                         {}

var emptyInfoView = infoStringView("")

func resolutionErrorView(res *resolution.ResolutionResult, errs []resolution.ResolutionError) tui.ViewModel {
	if len(errs) == 0 {
		return emptyInfoView
	}
	s := strings.Builder{}
	s.WriteString("The following errors were encountered during resolution which may impact results:\n")
	s.WriteString(resolutionErrorString(res, errs))

	return infoStringView(s.String())
}

type writeMsg struct {
	err error
}
