package osvscanner

import (
	"testing"
)

func TestIsRegexPattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		pattern  string
		expected bool
	}{
		{"simple regex", "/test/", true},
		{"complex regex", "/\\.git/", true},
		{"regex with pipe", "/node_modules|vendor/", true},
		{"glob pattern", "**/test/**", false},
		{"glob with stars", "*.go", false},
		{"empty string", "", false},
		{"single slash", "/", false},
		{"two slashes", "//", false},
		{"path starting with slash", "/usr/local", false},
		{"escaped trailing slash", "/test\\/", false},
		{"path ending with slash", "test/", false},
		{"path with slashes", "a/b/c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isRegexPattern(tt.pattern)
			if result != tt.expected {
				t.Errorf("isRegexPattern(%q) = %v, want %v", tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestParseExcludePatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		patterns       []string
		wantGlob       bool
		wantRegex      bool
		wantErr        bool
		globTestPath   string
		globTestMatch  bool
		regexTestPath  string
		regexTestMatch bool
	}{
		{
			name:          "single glob pattern",
			patterns:      []string{"**/test/**"},
			wantGlob:      true,
			wantRegex:     false,
			globTestPath:  "foo/test/bar",
			globTestMatch: true,
		},
		{
			name:           "single regex pattern",
			patterns:       []string{"/\\.git/"},
			wantGlob:       false,
			wantRegex:      true,
			regexTestPath:  ".git",
			regexTestMatch: true,
		},
		{
			name:           "mixed patterns",
			patterns:       []string{"**/vendor/**", "/node_modules/"},
			wantGlob:       true,
			wantRegex:      true,
			globTestPath:   "foo/vendor/bar",
			globTestMatch:  true,
			regexTestPath:  "node_modules",
			regexTestMatch: true,
		},
		{
			name:          "multiple glob patterns",
			patterns:      []string{"**/test/**", "**/docs/**"},
			wantGlob:      true,
			wantRegex:     false,
			globTestPath:  "foo/docs/readme",
			globTestMatch: true,
		},
		{
			name:           "multiple regex patterns",
			patterns:       []string{"/\\.git/", "/\\.cache/"},
			wantGlob:       false,
			wantRegex:      true,
			regexTestPath:  ".cache",
			regexTestMatch: true,
		},
		{
			name:      "empty patterns",
			patterns:  []string{},
			wantGlob:  false,
			wantRegex: false,
		},
		{
			name:     "invalid regex",
			patterns: []string{"/[invalid/"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseExcludePatterns(tt.patterns)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExcludePatterns() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if (result.GlobPattern != nil) != tt.wantGlob {
				t.Errorf("ParseExcludePatterns() GlobPattern present = %v, want %v", result.GlobPattern != nil, tt.wantGlob)
			}

			if (result.RegexPattern != nil) != tt.wantRegex {
				t.Errorf("ParseExcludePatterns() RegexPattern present = %v, want %v", result.RegexPattern != nil, tt.wantRegex)
			}

			// Test glob matching
			if tt.wantGlob && tt.globTestPath != "" {
				match := result.GlobPattern.Match(tt.globTestPath)
				if match != tt.globTestMatch {
					t.Errorf("GlobPattern.Match(%q) = %v, want %v", tt.globTestPath, match, tt.globTestMatch)
				}
			}

			// Test regex matching
			if tt.wantRegex && tt.regexTestPath != "" {
				match := result.RegexPattern.MatchString(tt.regexTestPath)
				if match != tt.regexTestMatch {
					t.Errorf("RegexPattern.MatchString(%q) = %v, want %v", tt.regexTestPath, match, tt.regexTestMatch)
				}
			}
		})
	}
}
