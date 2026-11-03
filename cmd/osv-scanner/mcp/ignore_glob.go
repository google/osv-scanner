package mcp

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gobwas/glob"
)

// maxDoublestarExpansions bounds combinatorial expansion of intermediate /**/ segments.
const maxDoublestarExpansions = 4

// compiledRule holds compiled glob matchers for a single ignore_glob_patterns entry.
type compiledRule struct {
	anchored     bool
	fileMatchers []glob.Glob
	dirMatchers  []glob.Glob
}

// compileIgnoreRule validates and compiles file and directory-subtree matchers for a single glob pattern.
func compileIgnoreRule(raw string) (compiledRule, error) {
	normalized := filepath.ToSlash(raw)
	for strings.HasPrefix(normalized, "./") {
		normalized = strings.TrimPrefix(normalized, "./")
	}

	if _, err := glob.Compile(normalized, '/'); err != nil {
		return compiledRule{}, fmt.Errorf("invalid ignore glob pattern %q: %w", raw, err)
	}

	anchored := strings.HasPrefix(normalized, "/") || filepath.IsAbs(raw)
	fileVariants := expandGlobVariants(normalized)
	fileMatchers, err := compileGlobList(fileVariants)
	if err != nil {
		return compiledRule{}, fmt.Errorf("invalid ignore glob pattern %q: %w", raw, err)
	}

	dirVariants := buildDirVariants(fileVariants)
	dirMatchers, err := compileGlobList(dirVariants)
	if err != nil {
		return compiledRule{}, fmt.Errorf("invalid ignore glob pattern %q: %w", raw, err)
	}

	return compiledRule{
		anchored:     anchored,
		fileMatchers: fileMatchers,
		dirMatchers:  dirMatchers,
	}, nil
}

// compileGlobList compiles a slice of slash-delimited glob strings.
func compileGlobList(patterns []string) ([]glob.Glob, error) {
	compiled := make([]glob.Glob, 0, len(patterns))
	for _, p := range patterns {
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, g)
	}

	return compiled, nil
}

// expandGlobVariants expands doublestar slash segments so zero-directory matches work with gobwas/glob.
func expandGlobVariants(pattern string) []string {
	base := []string{pattern}
	if strings.HasSuffix(pattern, "/") && pattern != "/" {
		base = append(base, pattern+"**")
	}

	expanded := make([]string, 0, len(base)*2)
	for _, item := range base {
		expanded = appendAllUnique(expanded, expandIntermediateDoublestars(item))
	}

	result := make([]string, 0, len(expanded)*2)
	for _, v := range expanded {
		result = appendUnique(result, v)
		if trimmed, ok := strings.CutPrefix(v, "**/"); ok {
			result = appendUnique(result, trimmed)
		}
	}

	return result
}

func expandIntermediateDoublestars(item string) []string {
	current := []string{item}
	for range maxDoublestarExpansions {
		next := make([]string, 0, len(current)*2)
		changed := false
		for _, candidate := range current {
			next = appendUnique(next, candidate)
			if before, after, ok := strings.Cut(candidate, "/**/"); ok {
				next = appendUnique(next, before+"/"+after)
				changed = true
			}
		}
		current = next
		if !changed {
			break
		}
	}

	return current
}

// buildDirVariants derives directory matchers capable of skipping an entire subtree.
func buildDirVariants(fileVariants []string) []string {
	var dirVariants []string
	for _, v := range fileVariants {
		trimmedSlash := strings.TrimSuffix(v, "/")
		if trimmedSlash != "" {
			dirVariants = appendUnique(dirVariants, trimmedSlash)
		}
		if prefix, ok := strings.CutSuffix(v, "/**"); ok && prefix != "" {
			dirVariants = appendUnique(dirVariants, prefix)
		}
	}

	return dirVariants
}

func appendUnique(list []string, item string) []string {
	if !slices.Contains(list, item) {
		list = append(list, item)
	}

	return list
}

func appendAllUnique(list, items []string) []string {
	for _, item := range items {
		list = appendUnique(list, item)
	}

	return list
}

func matchAnyGlob(matchers []glob.Glob, candidate string) bool {
	for _, m := range matchers {
		if m.Match(candidate) {
			return true
		}
	}

	return false
}
