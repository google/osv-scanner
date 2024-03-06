package fix

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
)

// TODO: currently, it's impossible to undo commands
// Need to think about how to support this

func interactiveMode(ctx context.Context, opts osvFixOptions) error {
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
