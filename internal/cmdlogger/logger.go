package cmdlogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError], assuming the logger is a [LoggerImpl].
//
// If the logger is not a [LoggerImpl], this will always return false.
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

type LoggerImpl struct {
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
func (c *LoggerImpl) SendEverythingToStderr() {
	c.everythingToStderr = true
}

func (c *LoggerImpl) SetLevel(level slog.Leveler) {
	c.Level = level
}

func (c *LoggerImpl) writer(level slog.Level) io.Writer {
	if c.everythingToStderr || level == slog.LevelError {
		return c.stderr
	}

	return c.stdout
}

func (c *LoggerImpl) Enabled(_ context.Context, level slog.Level) bool {
	if level == slog.LevelError {
		c.hasErrored = true
	}

	return level >= c.Level.Level()
}

func (c *LoggerImpl) Handle(_ context.Context, record slog.Record) error {
	if record.Level == slog.LevelError {
		c.hasErrored = true
	}

	_, err := fmt.Fprint(c.writer(record.Level), record.Message+"\n")

	return err
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError]
func (c *LoggerImpl) HasErrored() bool {
	return c.hasErrored
}

func (c *LoggerImpl) WithAttrs(_ []slog.Attr) slog.Handler {
	panic("not supported")
}

func (c *LoggerImpl) WithGroup(_ string) slog.Handler {
	panic("not supported")
}

var _ CmdLogger = &LoggerImpl{}

func New(stdout, stderr io.Writer) CmdLogger {
	return &LoggerImpl{
		stdout: stdout,
		stderr: stderr,
		Level:  slog.LevelInfo,
	}
}
