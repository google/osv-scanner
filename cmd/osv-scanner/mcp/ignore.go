package mcp

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// ignoreFilter evaluates candidate scan paths and results against ignore_glob_patterns.
type ignoreFilter struct {
	rules []compiledRule
	roots []string
}

// newIgnoreFilter compiles glob patterns and records directory scan roots for relative matching.
func newIgnoreFilter(patterns, scanPaths []string) (*ignoreFilter, error) {
	rules := make([]compiledRule, 0, len(patterns))
	for _, raw := range patterns {
		if raw == "" {
			continue
		}
		rule, err := compileIgnoreRule(raw)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	roots := make([]string, 0, len(scanPaths))
	for _, p := range scanPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		info, statErr := os.Stat(abs)
		if statErr == nil && info.IsDir() {
			roots = append(roots, filepath.ToSlash(filepath.Clean(abs)))
		}
	}

	return &ignoreFilter{
		rules: rules,
		roots: roots,
	}, nil
}

// isEmpty reports whether no ignore rules are active.
func (f *ignoreFilter) isEmpty() bool {
	return f == nil || len(f.rules) == 0
}

// matchesDir reports whether absDirSlash (under scan root rootSlash) should have its entire subtree skipped.
func (f *ignoreFilter) matchesDir(rootSlash, absDirSlash string) bool {
	if absDirSlash == rootSlash {
		for _, r := range f.rules {
			if r.anchored && matchAnyGlob(r.dirMatchers, absDirSlash) {
				return true
			}
		}

		return false
	}

	relSlash := strings.TrimPrefix(absDirSlash, rootSlash+"/")
	for _, r := range f.rules {
		if r.anchored {
			if matchAnyGlob(r.dirMatchers, absDirSlash) || matchAnyGlob(r.dirMatchers, "/"+relSlash) {
				return true
			}

			continue
		}
		if matchAnyGlob(r.dirMatchers, relSlash) {
			return true
		}
	}

	return false
}

// matchesDirectFile reports whether an explicit file target in input.Paths is ignored.
func (f *ignoreFilter) matchesDirectFile(rawPath, absFilePath string) bool {
	absSlash := filepath.ToSlash(filepath.Clean(absFilePath))
	rawSlash := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(rawPath)), "./")
	baseName := filepath.Base(absSlash)

	for _, r := range f.rules {
		if r.anchored {
			if matchAnyGlob(r.fileMatchers, absSlash) {
				return true
			}

			continue
		}
		if matchAnyGlob(r.fileMatchers, rawSlash) || matchAnyGlob(r.fileMatchers, absSlash) || matchAnyGlob(r.fileMatchers, baseName) {
			return true
		}
	}

	return false
}

// matchesSourcePath reports whether a discovered dependency source path matches any ignore rule.
func (f *ignoreFilter) matchesSourcePath(source models.SourceInfo) bool {
	cleaned := cleanSourcePath(source)
	matchedUnderRoot := false

	for _, rootSlash := range f.roots {
		prefix := rootSlash + "/"
		if !strings.HasPrefix(cleaned, prefix) {
			continue
		}
		matchedUnderRoot = true
		relSlash := strings.TrimPrefix(cleaned, prefix)
		if f.matchesRelativeSource(rootSlash, cleaned, relSlash) {
			return true
		}
	}

	if matchedUnderRoot {
		return false
	}

	return f.matchesDirectFile(cleaned, cleaned)
}

// matchesRelativeSource checks both file matchers and ancestor directory matchers relative to rootSlash.
func (f *ignoreFilter) matchesRelativeSource(rootSlash, absSlash, relSlash string) bool {
	for _, r := range f.rules {
		if r.anchored {
			if matchAnyGlob(r.fileMatchers, absSlash) || matchAnyGlob(r.fileMatchers, "/"+relSlash) {
				return true
			}

			continue
		}
		if matchAnyGlob(r.fileMatchers, relSlash) {
			return true
		}
	}

	parts := strings.Split(relSlash, "/")
	for i := 1; i < len(parts); i++ {
		ancestorRel := strings.Join(parts[:i], "/")
		if f.matchesDir(rootSlash, rootSlash+"/"+ancestorRel) {
			return true
		}
	}

	return false
}

// prepareScanTargets filters input.Paths and collects exact directory skip entries for osvscanner.ScannerActions.
func (f *ignoreFilter) prepareScanTargets(inputPaths []string, recursive bool) ([]string, []string, bool, error) {
	if f.isEmpty() {
		return inputPaths, nil, false, nil
	}

	keptPaths := make([]string, 0, len(inputPaths))
	var excludePatterns []string
	excludedAny := false

	for _, rawPath := range inputPaths {
		kept, skippedDirs, wasExcluded, err := f.classifyInputPath(rawPath, recursive)
		if err != nil {
			return nil, nil, false, err
		}
		if wasExcluded {
			excludedAny = true
			continue
		}
		if kept != "" {
			keptPaths = append(keptPaths, kept)
		}
		excludePatterns = appendAllUnique(excludePatterns, skippedDirs)
	}

	allExcluded := len(keptPaths) == 0 && excludedAny

	return keptPaths, excludePatterns, allExcluded, nil
}

func (f *ignoreFilter) classifyInputPath(rawPath string, recursive bool) (string, []string, bool, error) {
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return "", nil, false, err
	}
	info, statErr := os.Stat(absPath)
	if statErr != nil {
		// Defer missing or inaccessible target reporting to osvscanner.DoScan.
		return rawPath, nil, false, nil //nolint:nilerr
	}
	if !info.IsDir() {
		if f.matchesDirectFile(rawPath, absPath) {
			return "", nil, true, nil
		}

		return rawPath, nil, false, nil
	}

	rootSlash := filepath.ToSlash(filepath.Clean(absPath))
	if f.matchesDir(rootSlash, rootSlash) {
		return "", nil, true, nil
	}

	skippedDirs, walkErr := collectSkippedDirs(absPath, rootSlash, recursive, f)
	if walkErr != nil {
		return "", nil, false, walkErr
	}

	return rawPath, skippedDirs, false, nil
}

// collectSkippedDirs walks absRoot and returns exact directory skip arguments (prefixed with ":") for scalibr.
func collectSkippedDirs(absRoot, rootSlash string, recursive bool, filter *ignoreFilter) ([]string, error) {
	var skipped []string
	err := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if d != nil && d.IsDir() {
			dirSlash := filepath.ToSlash(filepath.Clean(path))
			if dirSlash != rootSlash {
				if filter.matchesDir(rootSlash, dirSlash) {
					skipped = append(skipped, ":"+path)
					return filepath.SkipDir
				}
				if !recursive {
					return filepath.SkipDir
				}
			}
		}
		if walkErr != nil {
			// Allow osvscanner.DoScan to handle unreadable non-ignored entries uniformly.
			return nil //nolint:nilerr
		}

		return nil
	})

	return skipped, err
}

// filterScanResults removes any PackageSource entries whose source path matches filter.
func filterScanResults(scanResults *models.VulnerabilityResults, filter *ignoreFilter) {
	if filter.isEmpty() {
		return
	}
	scanResults.Results = slices.DeleteFunc(scanResults.Results, func(ps models.PackageSource) bool {
		return filter.matchesSourcePath(ps.Source)
	})
}

// hasActionableVulns mirrors osvscanner's default error determination when ShowAllVulns is false.
func hasActionableVulns(scanResults *models.VulnerabilityResults) bool {
	for _, vf := range scanResults.Flatten() {
		if vf.Vulnerability != nil && vf.Vulnerability.GetId() != "" {
			if vf.GroupInfo.IsCalled() && !vf.GroupInfo.IsGroupUnimportant() {
				return true
			}
		}
		if len(vf.LicenseViolations) > 0 || vf.Deprecated {
			return true
		}
	}

	return false
}

// cleanSourcePath normalizes SourceInfo.Path and strips CycloneDX sub-location suffixes when present.
func cleanSourcePath(source models.SourceInfo) string {
	p := filepath.ToSlash(source.Path)
	if source.Type != models.SourceTypeSBOM {
		return p
	}
	searchStart := 0
	if len(p) >= 2 && p[1] == ':' {
		searchStart = 2
	}
	if idx := strings.IndexByte(p[searchStart:], ':'); idx >= 0 {
		return p[:searchStart+idx]
	}

	return p
}
