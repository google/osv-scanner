package gitlab

import (
	"encoding/json"
	"strings"

	"github.com/google/osv-scanner/v2/internal/utility/severity"
)

// SeverityLevel is the vulnerability severity level reported by scanner.
type SeverityLevel int

const (
	// SeverityLevelUndefined is a stub severity value for the case when it was not reported by scanner.
	SeverityLevelUndefined SeverityLevel = iota
	// SeverityLevelInfo represents the "info" or "ignore" severity level.
	SeverityLevelInfo
	// SeverityLevelUnknown represents the "experimental" or "unknown" severity level.
	SeverityLevelUnknown
	// SeverityLevelLow represents the "low" severity level.
	SeverityLevelLow
	// SeverityLevelMedium represents the "medium" severity level.
	SeverityLevelMedium
	// SeverityLevelHigh represents the "high" severity level.
	SeverityLevelHigh
	// SeverityLevelCritical represents the "critical" severity level.
	SeverityLevelCritical
)

// MarshalJSON converts a SeverityLevel value into the JSON representation
func (l SeverityLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// UnmarshalJSON parses a SeverityLevel value from JSON representation
func (l *SeverityLevel) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*l = ParseSeverityLevel(s)
	return nil
}

func (l SeverityLevel) String() string {
	switch l {
	case SeverityLevelCritical:
		return "Critical"
	case SeverityLevelHigh:
		return "High"
	case SeverityLevelMedium:
		return "Medium"
	case SeverityLevelLow:
		return "Low"
	case SeverityLevelInfo:
		return "Info"
	case SeverityLevelUnknown:
		return "Unknown"
	}
	return ""
}

// ParseSeverityLevel parses a SeverityLevel value from string
func ParseSeverityLevel(s string) SeverityLevel {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityLevelCritical
	case "high":
		return SeverityLevelHigh
	case "medium":
		return SeverityLevelMedium
	case "low":
		return SeverityLevelLow
	case "experimental", "unknown":
		return SeverityLevelUnknown
	case "ignore", "info":
		return SeverityLevelInfo
	default:
		return SeverityLevelUnknown
	}
}

func MapRatingToSeverityLevel(s string) SeverityLevel {
	switch s {
	case severity.CriticalRating.String():
		return SeverityLevelCritical
	case severity.HighRating.String():
		return SeverityLevelHigh
	case severity.MediumRating.String():
		return SeverityLevelMedium
	case severity.LowRating.String():
		return SeverityLevelLow
	case SeverityLevelInfo.String():
		return SeverityLevelInfo
	case severity.UnknownRating.String():
		return SeverityLevelUnknown
	default:
		return SeverityLevelUndefined
	}
}
