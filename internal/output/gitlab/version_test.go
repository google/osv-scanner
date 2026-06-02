package gitlab

import (
	"encoding/json"
	"testing"
)

func TestCurrentVersion(t *testing.T) {
	v := CurrentVersion()
	if v.Major != VersionMajor {
		t.Errorf("expected Major %d, got %d", VersionMajor, v.Major)
	}
	if v.Minor != VersionMinor {
		t.Errorf("expected Minor %d, got %d", VersionMinor, v.Minor)
	}
	if v.Patch != VersionPatch {
		t.Errorf("expected Patch %d, got %d", VersionPatch, v.Patch)
	}
}

func TestVersion_String(t *testing.T) {
	tests := []struct {
		name     string
		version  Version
		expected string
	}{
		{
			name:     "standard version",
			version:  Version{Major: 15, Minor: 2, Patch: 4},
			expected: "15.2.4",
		},
		{
			name:     "with pre-release",
			version:  Version{Major: 15, Minor: 2, Patch: 4, PreRelease: "beta1"},
			expected: "15.2.4-beta1",
		},
		{
			name:     "zero version",
			version:  Version{},
			expected: "0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.version.String(); got != tt.expected {
				t.Errorf("Version.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestVersion_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		version  Version
		expected string
	}{
		{
			name:     "standard version",
			version:  Version{Major: 15, Minor: 2, Patch: 4},
			expected: `"15.2.4"`,
		},
		{
			name:     "with pre-release",
			version:  Version{Major: 1, Minor: 0, Patch: 0, PreRelease: "rc1"},
			expected: `"1.0.0-rc1"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.version)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.expected {
				t.Errorf("MarshalJSON() = %v, want %v", string(got), tt.expected)
			}
		})
	}
}

func TestVersion_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Version
	}{
		{
			name:     "standard version",
			input:    `"15.2.4"`,
			expected: Version{Major: 15, Minor: 2, Patch: 4},
		},
		{
			name:     "with pre-release",
			input:    `"1.0.0-beta1"`,
			expected: Version{Major: 1, Minor: 0, Patch: 0, PreRelease: "beta1"},
		},
		{
			name:     "empty string uses defaults",
			input:    `""`,
			expected: Version{Major: VersionMajor, Minor: VersionMinor, Patch: VersionPatch},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Version
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
