package cmdlogger

import (
	"fmt"
	"log/slog"
)

func Debugf(msg string, args ...interface{}) {
	slog.Debug(fmt.Sprintf(msg, args...))
}

func Infof(msg string, args ...interface{}) {
	slog.Info(fmt.Sprintf(msg, args...))
}

func Warnf(msg string, args ...interface{}) {
	slog.Warn(fmt.Sprintf(msg, args...))
}

func Errorf(msg string, args ...interface{}) {
	slog.Error(fmt.Sprintf(msg, args...))
}
