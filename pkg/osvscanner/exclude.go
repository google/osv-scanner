package osvscanner

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
)

// ExcludePatterns holds compiled patterns for excluding directories/files
type ExcludePatterns struct {
	GlobPattern  glob.Glob            // Combined glob pattern using {p1,p2,...} syntax
	RegexPattern *cachedregexp.Regexp // Combined regex pattern using (p1|p2|...) syntax
}

// ParseExcludePatterns separates and compiles glob and regex patterns.
// Regex patterns are identified by /.../ syntax (like JavaScript).
func ParseExcludePatterns(patterns []string) (*ExcludePatterns, error) {
	var globPatterns []string
	var regexPatterns []string

	for _, p := range patterns {
		if isRegexPattern(p) {
			// Strip the leading and trailing slashes
			regex := p[1 : len(p)-1]
			regexPatterns = append(regexPatterns, regex)
		} else {
			globPatterns = append(globPatterns, p)
		}
	}

	result := &ExcludePatterns{}

	// Compile glob patterns using {p1,p2,...} syntax
	if len(globPatterns) > 0 {
		var combined string
		if len(globPatterns) == 1 {
			combined = globPatterns[0]
		} else {
			combined = "{" + strings.Join(globPatterns, ",") + "}"
		}
		g, err := glob.Compile(combined, '/')
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %q: %w", combined, err)
		}
		result.GlobPattern = g
	}

	// Compile regex patterns using (p1|p2|...) syntax
	if len(regexPatterns) > 0 {
		var combined string
		if len(regexPatterns) == 1 {
			combined = regexPatterns[0]
		} else {
			combined = "(" + strings.Join(regexPatterns, "|") + ")"
		}
		r, err := cachedregexp.Compile(combined)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", combined, err)
		}
		result.RegexPattern = r
	}

	return result, nil
}

// isRegexPattern checks if a pattern is wrapped in /.../ (JavaScript-style regex).
// Returns true if pattern starts and ends with '/' and has length >= 3.
func isRegexPattern(pattern string) bool {
	if len(pattern) < 3 {
		return false
	}
	if !strings.HasPrefix(pattern, "/") || !strings.HasSuffix(pattern, "/") {
		return false
	}
	// Check that the trailing slash is not escaped
	if strings.HasSuffix(pattern, "\\/") {
		return false
	}

	return true
}
