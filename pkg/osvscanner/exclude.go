package osvscanner

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/gobwas/glob"
)

// SkipDirPatterns holds parsed patterns for skipping directories during scanning.
// Supports three types of patterns:
//   - DirsToSkip: exact directory names to skip
//   - GlobPattern: glob patterns (g:pattern syntax)
//   - RegexPattern: regex patterns (r:pattern syntax)
type SkipDirPatterns struct {
	DirsToSkip   []string       // Exact directory names to skip
	GlobPattern  glob.Glob      // Combined glob pattern using {p1,p2,...} syntax
	RegexPattern *regexp.Regexp // Combined regex pattern using (p1|p2|...) syntax
}

// ParseSkipDirPatterns parses the skip directory patterns from command line.
// Pattern syntax (matching --lockfile flag style):
//   - "dirname" or ":dirname" -> exact directory name (DirsToSkip)
//   - "g:pattern" -> glob pattern (SkipDirGlob)
//   - "r:pattern" -> regex pattern (SkipDirRegex)
//
// The ":" prefix is an escape hatch for directory names containing colons.
func ParseSkipDirPatterns(patterns []string) (*SkipDirPatterns, error) {
	var dirsToSkip []string
	var globPatterns []string
	var regexPatterns []string

	for _, p := range patterns {
		patternType, pattern := parseSkipDirArg(p)

		switch patternType {
		case "":
			// Exact directory name
			dirsToSkip = append(dirsToSkip, pattern)
		case "g":
			globPatterns = append(globPatterns, pattern)
		case "r":
			regexPatterns = append(regexPatterns, pattern)
		default:
			return nil, fmt.Errorf("unknown pattern type %q in %q; use g: for glob or r: for regex", patternType, p)
		}
	}

	result := &SkipDirPatterns{
		DirsToSkip: dirsToSkip,
	}

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
		r, err := regexp.Compile(combined)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", combined, err)
		}
		result.RegexPattern = r
	}

	return result, nil
}

// parseSkipDirArg parses a single skip directory argument.
// Returns (patternType, pattern) where:
//   - patternType is "" for exact match, "g" for glob, "r" for regex, or the unknown prefix
//   - pattern is the actual pattern to use
//
// Unknown prefixes are returned as-is so the caller can provide appropriate error messages.
func parseSkipDirArg(arg string) (string, string) {
	// Handle Windows absolute paths (e.g., C:\path)
	if runtime.GOOS == "windows" && filepath.IsAbs(arg) {
		return "", arg
	}

	patternType, pattern, found := strings.Cut(arg, ":")
	if !found {
		// No colon found, treat as exact directory name
		return "", arg
	}

	// Empty prefix means exact match (escape hatch for paths with colons)
	// "g" prefix means glob pattern
	// "r" prefix means regex pattern
	// Return all prefixes (including unknown ones) to let the caller handle validation
	return patternType, pattern
}
