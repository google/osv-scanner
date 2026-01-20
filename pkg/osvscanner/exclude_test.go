package osvscanner

import (
	"testing"
)

func TestParseSkipDirArg(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		arg             string
		wantPatternType string
		wantPattern     string
	}{
		{"exact directory name", "test", "", "test"},
		{"exact with colon escape", ":test", "", "test"},
		{"glob pattern", "g:**/test/**", "g", "**/test/**"},
		{"regex pattern", "r:\\.git", "r", "\\.git"},
		{"regex with pipe", "r:node_modules|vendor", "r", "node_modules|vendor"},
		{"empty string", "", "", ""},
		{"directory with colon escape", ":my:project", "", "my:project"},
		{"single letter dir", "g", "", "g"},
		{"path like glob", "test/path", "", "test/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			patternType, pattern := parseSkipDirArg(tt.arg)
			if patternType != tt.wantPatternType {
				t.Errorf("parseSkipDirArg(%q) patternType = %q, want %q", tt.arg, patternType, tt.wantPatternType)
			}
			if pattern != tt.wantPattern {
				t.Errorf("parseSkipDirArg(%q) pattern = %q, want %q", tt.arg, pattern, tt.wantPattern)
			}
		})
	}
}

func TestParseSkipDirPatterns(t *testing.T) {
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
			name:      "single exact directory",
			patterns:  []string{"test"},
			wantDirs:  true,
			wantGlob:  false,
			wantRegex: false,
			dirsCount: 1,
		},
		{
			name:      "multiple exact directories",
			patterns:  []string{"test", "docs", "vendor"},
			wantDirs:  true,
			wantGlob:  false,
			wantRegex: false,
			dirsCount: 3,
		},
		{
			name:          "single glob pattern",
			patterns:      []string{"g:**/test/**"},
			wantDirs:      false,
			wantGlob:      true,
			wantRegex:     false,
			globTestPath:  "foo/test/bar",
			globTestMatch: true,
		},
		{
			name:           "single regex pattern",
			patterns:       []string{"r:\\.git"},
			wantDirs:       false,
			wantGlob:       false,
			wantRegex:      true,
			regexTestPath:  ".git",
			regexTestMatch: true,
		},
		{
			name:           "mixed patterns",
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
			name:          "multiple glob patterns",
			patterns:      []string{"g:**/test/**", "g:**/docs/**"},
			wantDirs:      false,
			wantGlob:      true,
			wantRegex:     false,
			globTestPath:  "foo/docs/readme",
			globTestMatch: true,
		},
		{
			name:           "multiple regex patterns",
			patterns:       []string{"r:\\.git", "r:\\.cache"},
			wantDirs:       false,
			wantGlob:       false,
			wantRegex:      true,
			regexTestPath:  ".cache",
			regexTestMatch: true,
		},
		{
			name:      "empty patterns",
			patterns:  []string{},
			wantDirs:  false,
			wantGlob:  false,
			wantRegex: false,
		},
		{
			name:     "invalid regex",
			patterns: []string{"r:[invalid"},
			wantErr:  true,
		},
		{
			name:      "colon escape for exact match",
			patterns:  []string{":my:project"},
			wantDirs:  true,
			wantGlob:  false,
			wantRegex: false,
			dirsCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseSkipDirPatterns(tt.patterns)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSkipDirPatterns() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if (len(result.DirsToSkip) > 0) != tt.wantDirs {
				t.Errorf("ParseSkipDirPatterns() DirsToSkip present = %v, want %v", len(result.DirsToSkip) > 0, tt.wantDirs)
			}

			if tt.wantDirs && len(result.DirsToSkip) != tt.dirsCount {
				t.Errorf("ParseSkipDirPatterns() DirsToSkip count = %d, want %d", len(result.DirsToSkip), tt.dirsCount)
			}

			if (result.GlobPattern != nil) != tt.wantGlob {
				t.Errorf("ParseSkipDirPatterns() GlobPattern present = %v, want %v", result.GlobPattern != nil, tt.wantGlob)
			}

			if (result.RegexPattern != nil) != tt.wantRegex {
				t.Errorf("ParseSkipDirPatterns() RegexPattern present = %v, want %v", result.RegexPattern != nil, tt.wantRegex)
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
