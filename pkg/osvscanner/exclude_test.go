package osvscanner

import (
	"testing"
)

func TestParseExcludeArg(t *testing.T) {
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

func TestParseExcludePatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		patterns       []string
		wantDirs       bool
		wantGlob       bool
		wantRegex      bool
		wantErr        bool
		dirsCount      int
		globTestPath   string
		globTestMatch  bool
		regexTestPath  string
		regexTestMatch bool
	}{
		{
			name:      "single_exact_directory",
			patterns:  []string{"test"},
			wantDirs:  true,
			wantGlob:  false,
			wantRegex: false,
			dirsCount: 1,
		},
		{
			name:      "multiple_exact_directories",
			patterns:  []string{"test", "docs", "vendor"},
			wantDirs:  true,
			wantGlob:  false,
			wantRegex: false,
			dirsCount: 3,
		},
		{
			name:          "single_glob_pattern",
			patterns:      []string{"g:**/test/**"},
			wantDirs:      false,
			wantGlob:      true,
			wantRegex:     false,
			globTestPath:  "foo/test/bar",
			globTestMatch: true,
		},
		{
			name:           "single_regex_pattern",
			patterns:       []string{"r:\\.git"},
			wantDirs:       false,
			wantGlob:       false,
			wantRegex:      true,
			regexTestPath:  ".git",
			regexTestMatch: true,
		},
		{
			name:           "mixed_patterns",
			patterns:       []string{"vendor", "g:**/test/**", "r:node_modules"},
			wantDirs:       true,
			wantGlob:       true,
			wantRegex:      true,
			dirsCount:      1,
			globTestPath:   "foo/test/bar",
			globTestMatch:  true,
			regexTestPath:  "node_modules",
			regexTestMatch: true,
		},
		{
			name:          "multiple_glob_patterns",
			patterns:      []string{"g:**/test/**", "g:**/docs/**"},
			wantDirs:      false,
			wantGlob:      true,
			wantRegex:     false,
			globTestPath:  "foo/docs/readme",
			globTestMatch: true,
		},
		{
			name:           "multiple_regex_patterns",
			patterns:       []string{"r:\\.git", "r:\\.cache"},
			wantDirs:       false,
			wantGlob:       false,
			wantRegex:      true,
			regexTestPath:  ".cache",
			regexTestMatch: true,
		},
		{
			name:      "empty_patterns",
			patterns:  []string{},
			wantDirs:  false,
			wantGlob:  false,
			wantRegex: false,
		},
		{
			name:     "invalid_regex",
			patterns: []string{"r:[invalid"},
			wantErr:  true,
		},
		{
			name:      "colon_escape_for_exact_match",
			patterns:  []string{":my:project"},
			wantDirs:  true,
			wantGlob:  false,
			wantRegex: false,
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
			result, err := ParseExcludePatterns(tt.patterns)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExcludePatterns() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if (len(result.DirsToSkip) > 0) != tt.wantDirs {
				t.Errorf("ParseExcludePatterns() DirsToSkip present = %v, want %v", len(result.DirsToSkip) > 0, tt.wantDirs)
			}

			if tt.wantDirs && len(result.DirsToSkip) != tt.dirsCount {
				t.Errorf("ParseExcludePatterns() DirsToSkip count = %d, want %d", len(result.DirsToSkip), tt.dirsCount)
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
