package osvscanner

import (
	"testing"
)

func Test_parseExcludeArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		arg             string
		wantPatternType string
		wantPattern     string
	}{
		{"exact_directory_name", "test", "", "test"},
		{"exact_with_colon_escape", ":test", "", "test"},
		{"glob_pattern", "g:**/test/**", "g", "**/test/**"},
		{"regex_pattern", "r:\\.git", "r", "\\.git"},
		{"regex_with_pipe", "r:node_modules|vendor", "r", "node_modules|vendor"},
		{"empty_string", "", "", ""},
		{"directory_with_colon_escape", ":my:project", "", "my:project"},
		{"single_letter_dir", "g", "", "g"},
		{"path_like_glob", "test/path", "", "test/path"},
		{"unknown_prefix_returns_prefix", "x:pattern", "x", "pattern"},
		// Windows specific tests - these will run on Linux too but result might depend on OS
		// We expect r: to be regex on ALL platforms now with the fix (since it falls through on Linux, and matches explicit check on Windows)
		{"windows_regex_lower_r", `r:pattern`, "r", "pattern"},
		{"windows_glob_lower_g", `g:pattern`, "g", "pattern"},
		{"windows_regex_simple", `r:foo`, "r", "foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			patternType, pattern := parseExcludeArg(tt.arg)
			if patternType != tt.wantPatternType {
				t.Errorf("parseExcludeArg(%q) patternType = %q, want %q", tt.arg, patternType, tt.wantPatternType)
			}
			if pattern != tt.wantPattern {
				t.Errorf("parseExcludeArg(%q) pattern = %q, want %q", tt.arg, pattern, tt.wantPattern)
			}
		})
	}
}

func Test_parseExcludePatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		patterns      []string
		wantErr       bool
		dirsCount     int
		globTestPath  string
		regexTestPath string
	}{
		{
			name:      "single_exact_directory",
			patterns:  []string{"test"},
			dirsCount: 1,
		},
		{
			name:      "multiple_exact_directories",
			patterns:  []string{"test", "docs", "vendor"},
			dirsCount: 3,
		},
		{
			name:         "single_glob_pattern",
			patterns:     []string{"g:**/test/**"},
			globTestPath: "foo/test/bar",
		},
		{
			name:          "single_regex_pattern",
			patterns:      []string{"r:\\.git"},
			regexTestPath: ".git",
		},
		{
			name:          "mixed_patterns",
			patterns:      []string{"vendor", "g:**/test/**", "r:node_modules"},
			dirsCount:     1,
			globTestPath:  "foo/test/bar",
			regexTestPath: "node_modules",
		},
		{
			name:         "multiple_glob_patterns",
			patterns:     []string{"g:**/test/**", "g:**/docs/**"},
			globTestPath: "foo/docs/readme",
		},
		{
			name:          "multiple_regex_patterns",
			patterns:      []string{"r:\\.git", "r:\\.cache"},
			regexTestPath: ".cache",
		},
		{
			name:     "empty_patterns",
			patterns: []string{},
		},
		{
			name:     "invalid_regex",
			patterns: []string{"r:[invalid"},
			wantErr:  true,
		},
		{
			name:      "colon_escape_for_exact_match",
			patterns:  []string{":my:project"},
			dirsCount: 1,
		},
		{
			name:     "unknown_prefix_returns_error",
			patterns: []string{"x:pattern"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := parseExcludePatterns(tt.patterns)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseExcludePatterns() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check dirs count
			if len(result.dirsToSkip) != tt.dirsCount {
				t.Errorf("parseExcludePatterns() dirsToSkip count = %d, want %d", len(result.dirsToSkip), tt.dirsCount)
			}

			// Check glob pattern presence and matching
			wantGlob := tt.globTestPath != ""
			if (result.globPattern != nil) != wantGlob {
				t.Errorf("parseExcludePatterns() globPattern present = %v, want %v", result.globPattern != nil, wantGlob)
			}
			if wantGlob && result.globPattern != nil {
				if !result.globPattern.Match(tt.globTestPath) {
					t.Errorf("globPattern.Match(%q) = false, want true", tt.globTestPath)
				}
			}

			// Check regex pattern presence and matching
			wantRegex := tt.regexTestPath != ""
			if (result.regexPattern != nil) != wantRegex {
				t.Errorf("parseExcludePatterns() regexPattern present = %v, want %v", result.regexPattern != nil, wantRegex)
			}
			if wantRegex && result.regexPattern != nil {
				if !result.regexPattern.MatchString(tt.regexTestPath) {
					t.Errorf("regexPattern.MatchString(%q) = false, want true", tt.regexTestPath)
				}
			}
		})
	}
}
