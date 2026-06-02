package gitlab

import (
	"encoding/json"
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/severity"
)

func TestSeverityLevel_String(t *testing.T) {
	tests := []struct {
		level    SeverityLevel
		expected string
	}{
		{SeverityLevelCritical, "Critical"},
		{SeverityLevelHigh, "High"},
		{SeverityLevelMedium, "Medium"},
		{SeverityLevelLow, "Low"},
		{SeverityLevelInfo, "Info"},
		{SeverityLevelUnknown, "Unknown"},
		{SeverityLevelUndefined, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("SeverityLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSeverityLevel_MarshalJSON(t *testing.T) {
	tests := []struct {
		level    SeverityLevel
		expected string
	}{
		{SeverityLevelCritical, `"Critical"`},
		{SeverityLevelHigh, `"High"`},
		{SeverityLevelMedium, `"Medium"`},
		{SeverityLevelLow, `"Low"`},
		{SeverityLevelUnknown, `"Unknown"`},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got, err := json.Marshal(tt.level)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.expected {
				t.Errorf("MarshalJSON() = %v, want %v", string(got), tt.expected)
			}
		})
	}
}

func TestSeverityLevel_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		input    string
		expected SeverityLevel
	}{
		{`"Critical"`, SeverityLevelCritical},
		{`"critical"`, SeverityLevelCritical},
		{`"High"`, SeverityLevelHigh},
		{`"Medium"`, SeverityLevelMedium},
		{`"Low"`, SeverityLevelLow},
		{`"Info"`, SeverityLevelInfo},
		{`"ignore"`, SeverityLevelInfo},
		{`"Unknown"`, SeverityLevelUnknown},
		{`"experimental"`, SeverityLevelUnknown},
		{`"invalid"`, SeverityLevelUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var got SeverityLevel
			err := json.Unmarshal([]byte(tt.input), &got)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("UnmarshalJSON() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseSeverityLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected SeverityLevel
	}{
		{"critical", SeverityLevelCritical},
		{"CRITICAL", SeverityLevelCritical},
		{"high", SeverityLevelHigh},
		{"medium", SeverityLevelMedium},
		{"low", SeverityLevelLow},
		{"info", SeverityLevelInfo},
		{"ignore", SeverityLevelInfo},
		{"unknown", SeverityLevelUnknown},
		{"experimental", SeverityLevelUnknown},
		{"something-else", SeverityLevelUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseSeverityLevel(tt.input); got != tt.expected {
				t.Errorf("ParseSeverityLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMapRatingToSeverityLevel(t *testing.T) {
	tests := []struct {
		rating   string
		expected SeverityLevel
	}{
		{severity.CriticalRating.String(), SeverityLevelCritical},
		{severity.HighRating.String(), SeverityLevelHigh},
		{severity.MediumRating.String(), SeverityLevelMedium},
		{severity.LowRating.String(), SeverityLevelLow},
		{severity.UnknownRating.String(), SeverityLevelUnknown},
		{"Info", SeverityLevelInfo},
		{"invalid", SeverityLevelUndefined},
	}

	for _, tt := range tests {
		t.Run(tt.rating, func(t *testing.T) {
			if got := MapRatingToSeverityLevel(tt.rating); got != tt.expected {
				t.Errorf("MapRatingToSeverityLevel(%q) = %v, want %v", tt.rating, got, tt.expected)
			}
		})
	}
}
