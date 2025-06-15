package cmdlogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
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

func (c *Handler) Enabled(_ context.Context, level slog.Level) bool {
	if level == slog.LevelError {
		c.hasErrored = true
	}

	return level >= c.Level.Level()
}

func (c *Handler) Handle(_ context.Context, record slog.Record) error {
	if record.Level == slog.LevelError {
		c.hasErrored = true

		if strings.HasPrefix(record.Message, "Ignored invalid config file") {
			c.hasErroredBecauseInvalidConfig = true
		}
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

func (c *Handler) WithAttrs(_ []slog.Attr) slog.Handler {
	panic("not supported")
}

func (c *Handler) WithGroup(_ string) slog.Handler {
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
