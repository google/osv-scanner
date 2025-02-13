package clilogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

type CLILogger struct {
	stdout        io.Writer
	stderr        io.Writer
	stdoutHandler slog.Handler
	stderrHandler slog.Handler
	hasErrored    bool
}

// handler returns the log handler to use for the given level
func (c CLILogger) handler(level slog.Level) slog.Handler {
	if level == slog.LevelInfo {
		return c.stdoutHandler
	}

	return c.stderrHandler
}

func (c CLILogger) writer(level slog.Level) io.Writer {
	if level == slog.LevelInfo {
		return c.stdout
	}

	return c.stderr
}

func (c CLILogger) Enabled(ctx context.Context, level slog.Level) bool {
	return c.handler(level).Enabled(ctx, level)
}

func (c CLILogger) Handle(_ context.Context, record slog.Record) error {
	if record.Level == slog.LevelError {
		c.hasErrored = true
	}

	_, err := fmt.Fprint(c.writer(record.Level), record.Message)

	return err
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError]
func (c CLILogger) HasErrored() bool {
	return c.hasErrored
}

func (c CLILogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return CLILogger{
		stdout:        c.stdout,
		stderr:        c.stderr,
		stdoutHandler: c.stdoutHandler.WithAttrs(attrs),
		stderrHandler: c.stderrHandler.WithAttrs(attrs),
	}
}

func (c CLILogger) WithGroup(name string) slog.Handler {
	return CLILogger{
		stdout:        c.stdout,
		stderr:        c.stderr,
		stdoutHandler: c.stdoutHandler.WithGroup(name),
		stderrHandler: c.stderrHandler.WithGroup(name),
	}
}

var _ slog.Handler = CLILogger{}

func New(stdout, stderr io.Writer) CLILogger {
	return CLILogger{
		stdout:        stdout,
		stderr:        stderr,
		stdoutHandler: slog.NewTextHandler(stdout, nil),
		stderrHandler: slog.NewTextHandler(stderr, nil),
	}
}
