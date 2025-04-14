// Package testlogger provides a slog handler which can handle t.Parallel() tests while being a global logging handler,
// redirecting it to the correct underlying logger for each test thread.
package testlogger

import (
	"bufio"
	"bytes"
	"context"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"log/slog"
	"runtime"
	"strings"
	"sync"
)

// TestLogger can be set as the global logging handler before the test starts, and individual test cases can add their
// own instance/implementation of the cmdlogger.CmdLogger interface.
type TestLogger struct {
	loggerMap sync.Map // map[string]cmdlogger.CmdLogger
}

func (tl *TestLogger) getLogger() cmdlogger.CmdLogger {
	key := getCallerInstance()
	val, ok := tl.loggerMap.Load(key)
	if !ok {
		panic("logger not found: " + key)
	}

	return val.(cmdlogger.CmdLogger)
}

// AddInstance adds a "global" logger to this specific test run.
func (tl *TestLogger) AddInstance(logger cmdlogger.CmdLogger) {
	key := getCallerInstance()
	prev, _ := tl.loggerMap.Swap(key, &logger)
	if prev != nil {
		// This is used as a safety check for incorrect usage of the TestLogger, and should never happen
		// during actual tests if Delete() is correctly called at the end of a test.
		panic("same logger being added twice")
	}
}

// Delete removes the logger created by AddInstance()
// This **must** be called before a test ends, as the same memory address may be reused.
func (tl *TestLogger) Delete() {
	tl.loggerMap.Delete(getCallerInstance())
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

var _ cmdlogger.CmdLogger = &TestLogger{}

func New() *TestLogger {
	return &TestLogger{
		loggerMap: sync.Map{},
	}
}

// getCallerInstance finds in the call stack the memory address of the initial test runner call.
// It will look something like this:
//
// `testing.tRunner(0x12345678, 0x98765432)`
//
// This is safe to be used as a key, as the first pointer address must be unique
// while this test is running, and will only be reused after the test exists and that address is garbage collected.
//
// Because this inspects the stack trace, if there is a very deep recursive function, this will not be able to find the
// correct caller instance. Currently there is no solution to this.
func getCallerInstance() string {
	var buf [8192]byte
	runtime.Stack(buf[:], false)
	n := runtime.Stack(buf[:], false)
	sc := bufio.NewScanner(bytes.NewReader(buf[:n]))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "testing.tRunner(") {
			return sc.Text()
		}
	}

	panic("no caller found in stack, recursed too deep?")
}
