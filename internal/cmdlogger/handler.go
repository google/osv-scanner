package cmdlogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

var (
	GlobalHandler slog.Handler
	GlobalLogger  *slog.Logger
)

type Handler struct {
	stdout             io.Writer
	stderr             io.Writer
	hasErrored         bool
	everythingToStderr bool
	Level              slog.Leveler

	hasErroredBecauseInvalidConfig bool
}

// SendEverythingToStderr tells the logger to send all logs to stderr regardless
// of their level.
//
// This is useful if we're expecting to output structured data to stdout such
// as JSON, which cannot be mixed with other output.
func (c *Handler) SendEverythingToStderr() {
	c.everythingToStderr = true
}

func (c *Handler) SetLevel(level slog.Leveler) {
	c.Level = level
}

func (c *Handler) writer(level slog.Level) io.Writer {
	if c.everythingToStderr || level == slog.LevelError {
		return c.stderr
	}

	return c.stdout
}

func (c *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	if level == slog.LevelError {
		c.hasErrored = true
	}

	if GlobalHandler != nil {
		return GlobalHandler.Enabled(ctx, level)
	}

	return level >= c.Level.Level()
}

func (c *Handler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level == slog.LevelError {
		c.hasErrored = true

		if strings.HasPrefix(record.Message, "Ignored invalid config file") {
			c.hasErroredBecauseInvalidConfig = true
		}
	}

	if GlobalHandler != nil {
		return GlobalHandler.Handle(ctx, record)
	}

	_, err := fmt.Fprint(c.writer(record.Level), record.Message+"\n")

	return err
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError]
func (c *Handler) HasErrored() bool {
	return c.hasErrored
}

// HasErroredBecauseInvalidConfig returns true if there have been any calls to
// Handle with a level of [slog.LevelError] due to a config file being invalid
func (c *Handler) HasErroredBecauseInvalidConfig() bool {
	return c.hasErroredBecauseInvalidConfig
}

func (c *Handler) WithAttrs(a []slog.Attr) slog.Handler {
	if GlobalHandler != nil {
		return GlobalHandler.WithAttrs(a)
	}
	panic("not supported")
}

func (c *Handler) WithGroup(g string) slog.Handler {
	if GlobalHandler != nil {
		return GlobalHandler.WithGroup(g)
	}
	panic("not supported")
}

var _ CmdLogger = &Handler{}

func New(stdout, stderr io.Writer) CmdLogger {
	return &Handler{
		stdout: stdout,
		stderr: stderr,
		Level:  slog.LevelInfo,
	}
}
