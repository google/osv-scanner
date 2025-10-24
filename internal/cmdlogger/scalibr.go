package cmdlogger

import (
	"fmt"
	"log/slog"

	"github.com/google/osv-scalibr/log"
)

var _ log.Logger = &ScalibrAdapter{}

type ScalibrAdapter struct {
	Logger *slog.Logger
}

func (s *ScalibrAdapter) Errorf(format string, args ...any) {
	s.Logger.Error(fmt.Sprintf(format, args...))
}

func (s *ScalibrAdapter) Error(args ...any) {
	s.Logger.Error(fmt.Sprint(args...))
}

func (s *ScalibrAdapter) Warnf(format string, args ...any) {
	s.Logger.Warn(fmt.Sprintf(format, args...))
}

func (s *ScalibrAdapter) Warn(args ...any) {
	s.Logger.Warn(fmt.Sprint(args...))
}

func (s *ScalibrAdapter) Infof(format string, args ...any) {
	s.Logger.Info(fmt.Sprintf(format, args...))
}

func (s *ScalibrAdapter) Info(args ...any) {
	s.Logger.Info(fmt.Sprint(args...))
}

func (s *ScalibrAdapter) Debugf(format string, args ...any) {
	s.Logger.Debug(fmt.Sprintf(format, args...))
}

func (s *ScalibrAdapter) Debug(args ...any) {
	s.Logger.Debug(fmt.Sprint(args...))
}
