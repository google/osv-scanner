package testlogger

import (
	"context"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"io"
	"log/slog"
	"sync"
)

type TestLogger struct {
	loggerMap sync.Map
}

func (tl *TestLogger) AddInstance(stdout, stderr io.Writer) {
	key := getCallerInstance()
	logger := cmdlogger.New(stdout, stderr)
	prev, _ := tl.loggerMap.Swap(key, &logger)
	if prev != nil {
		panic("same logger being added twice")
	}
}

func (tl *TestLogger) Delete() {
	tl.loggerMap.Delete(getCallerInstance())
}

func (tl *TestLogger) getLogger() *cmdlogger.LoggerImpl {
	key := getCallerInstance()
	val, ok := tl.loggerMap.Load(key)
	if !ok {
		panic("logger not found: " + key)
	}

	return val.(*cmdlogger.LoggerImpl)
}

// SendEverythingToStderr tells the logger to send all logs to stderr regardless
// of their level.
//
// This is useful if we're expecting to output structured data to stdout such
// as JSON, which cannot be mixed with other output.
func (tl *TestLogger) SendEverythingToStderr() {
	tl.getLogger().SendEverythingToStderr()
}

func (tl *TestLogger) SetLevel(level slog.Leveler) {
	tl.getLogger().SetLevel(level)
}

func (tl *TestLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return tl.getLogger().Enabled(ctx, level)
}

func (tl *TestLogger) Handle(ctx context.Context, record slog.Record) error {
	return tl.getLogger().Handle(ctx, record)
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError]
func (tl *TestLogger) HasErrored() bool {
	return tl.getLogger().HasErrored()
}

func (tl *TestLogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return tl.getLogger().WithAttrs(attrs)
}

func (tl *TestLogger) WithGroup(g string) slog.Handler {
	return tl.getLogger().WithGroup(g)
}

var _ slog.Handler = &TestLogger{}
var _ cmdlogger.CmdLogger = &TestLogger{}

func New() *TestLogger {
	return &TestLogger{
		loggerMap: sync.Map{},
	}
}
