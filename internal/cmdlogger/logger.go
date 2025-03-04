package cmdlogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// SendEverythingToStderr tells the logger (if its in use) to send all logs
// to stderr regardless of their level.
//
// This is useful if we're expecting to output structured data to stdout such
// as JSON, which cannot be mixed with other output.
func SendEverythingToStderr() {
	l, ok := slog.Default().Handler().(*CmdLogger)

	if ok {
		l.SendEverythingToStderr()
	}
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError], assuming the logger is a [CmdLogger].
//
// If the logger is not a [CmdLogger], this will always return false.
func HasErrored() bool {
	l, ok := slog.Default().Handler().(*CmdLogger)

	if ok {
		return l.HasErrored()
	}

	return false
}

func SetLevel(level slog.Leveler) {
	l, ok := slog.Default().Handler().(*CmdLogger)

	if ok {
		l.Level = level
	}
}

type CmdLogger struct {
	stdout             io.Writer
	stderr             io.Writer
	hasErrored         bool
	everythingToStderr bool
	Level              slog.Leveler
}

// SendEverythingToStderr tells the logger to send all logs to stderr regardless
// of their level.
//
// This is useful if we're expecting to output structured data to stdout such
// as JSON, which cannot be mixed with other output.
func (c *CmdLogger) SendEverythingToStderr() {
	c.everythingToStderr = true
}

func (c *CmdLogger) writer(level slog.Level) io.Writer {
	if c.everythingToStderr || level == slog.LevelError {
		return c.stderr
	}

	return c.stdout
}

func (c *CmdLogger) Enabled(_ context.Context, level slog.Level) bool {
	if level == slog.LevelError {
		c.hasErrored = true
	}

	return level >= c.Level.Level()
}

func (c *CmdLogger) Handle(_ context.Context, record slog.Record) error {
	if record.Level == slog.LevelError {
		c.hasErrored = true
	}

	_, err := fmt.Fprint(c.writer(record.Level), record.Message)

	return err
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError]
func (c *CmdLogger) HasErrored() bool {
	return c.hasErrored
}

func (c *CmdLogger) WithAttrs(_ []slog.Attr) slog.Handler {
	panic("not supported")
}

func (c *CmdLogger) WithGroup(_ string) slog.Handler {
	panic("not supported")
}

var _ slog.Handler = &CmdLogger{}

func New(stdout, stderr io.Writer) CmdLogger {
	return CmdLogger{
		stdout: stdout,
		stderr: stderr,
		Level:  slog.LevelInfo,
	}
}
