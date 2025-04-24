package cmdlogger

import "log/slog"

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError], assuming the logger is a [Handler].
//
// If the logger is not a [Handler], this will always return false.
func HasErrored() bool {
	l, ok := slog.Default().Handler().(CmdLogger)

	if ok {
		return l.HasErrored()
	}

	return false
}

func SetLevel(level slog.Leveler) {
	l, ok := slog.Default().Handler().(CmdLogger)

	if ok {
		l.SetLevel(level)
	}
}
