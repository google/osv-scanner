// Package cmdlogger provides wrapper for slog logging commands.
package cmdlogger

import (
	"cmp"
	"fmt"
	"log/slog"
)

func Debugf(msg string, args ...any) {
	logger := cmp.Or(GlobalLogger, slog.Default())
	logger.Debug(fmt.Sprintf(msg, args...))
}

func Infof(msg string, args ...any) {
	logger := cmp.Or(GlobalLogger, slog.Default())
	logger.Info(fmt.Sprintf(msg, args...))
}

func Warnf(msg string, args ...any) {
	logger := cmp.Or(GlobalLogger, slog.Default())
	logger.Warn(fmt.Sprintf(msg, args...))
}

func Errorf(msg string, args ...any) {
	logger := cmp.Or(GlobalLogger, slog.Default())
	logger.Error(fmt.Sprintf(msg, args...))
}
