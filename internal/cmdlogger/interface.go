package cmdlogger

import "log/slog"

type CmdLogger interface {
	slog.Handler
	SendEverythingToStderr()
	HasErrored() bool
	HasErroredBecauseInvalidConfig() bool
	SetLevel(level slog.Leveler)
}

// SendEverythingToStderr tells the logger (if its in use) to send all logs
// to stderr regardless of their level.
//
// This is useful if we're expecting to output structured data to stdout such
// as JSON, which cannot be mixed with other output.
func SendEverythingToStderr() {
	l, ok := slog.Default().Handler().(CmdLogger)

	if ok {
		l.SendEverythingToStderr()
	}
}
