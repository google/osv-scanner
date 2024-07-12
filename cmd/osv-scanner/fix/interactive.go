package fix

import (
	"context"
	"errors"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scanner/internal/remediation"
)

// TODO: currently, it's impossible to undo commands
// Need to think about how to support this

func interactiveMode(ctx context.Context, opts osvFixOptions) error {
	if !remediation.SupportsRelax(opts.ManifestRW) && !remediation.SupportsInPlace(opts.LockfileRW) {
		return errors.New("no supported remediation strategies found")
	}

	cl := opts.Client
	p := tea.NewProgram(newModel(ctx, opts, cl), tea.WithAltScreen())
	m, err := p.Run()
	if err != nil {
		return err
	}
	// It doesn't look like it's possible to make p.Run() return a custom error,
	// so we store fatal errors on the model itself.
	return m.(model).err
}
