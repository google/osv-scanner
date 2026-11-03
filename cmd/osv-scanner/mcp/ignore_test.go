package mcp

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const (
	rootLockfileJSON = `{
  "requires": true,
  "lockfileVersion": 1,
  "dependencies": {
    "ansi-html": {
      "version": "0.0.1",
      "resolved": "https://registry.npmjs.org/ansi-html/-/ansi-html-0.0.1.tgz"
    }
  }
}
`
	excludedLockfileJSON = `{
  "requires": true,
  "lockfileVersion": 1,
  "dependencies": {
    "minimist": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"
    }
  }
}
`
)

// createTwoSubtreeFixture creates a temporary project with root/included and child/excluded lockfiles.
func createTwoSubtreeFixture(t *testing.T, childDirName string) (string, string, string) {
	t.Helper()
	baseDir := t.TempDir()
	rootLock := filepath.Join(baseDir, "package-lock.json")
	if err := os.WriteFile(rootLock, []byte(rootLockfileJSON), 0o600); err != nil {
		t.Fatalf("failed to write root lockfile: %v", err)
	}

	childDir := filepath.Join(baseDir, childDirName)
	if err := os.MkdirAll(childDir, 0o750); err != nil {
		t.Fatalf("failed to create child directory: %v", err)
	}
	childLock := filepath.Join(childDir, "package-lock.json")
	if err := os.WriteFile(childLock, []byte(excludedLockfileJSON), 0o600); err != nil {
		t.Fatalf("failed to write child lockfile: %v", err)
	}

	return baseDir, rootLock, childLock
}

// connectInMemoryMCP starts an in-memory MCP server and client session for end-to-end tool tests.
func connectInMemoryMCP(t *testing.T) *mcp.ClientSession {
	t.Helper()
	osvscanner.SetLogger(slog.NewTextHandler(os.Stderr, nil))
	ctx := t.Context()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	srv := newServer()
	go func() {
		_ = srv.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-unit-test-client",
		Version: "1.0.0",
	}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("failed to connect in-memory MCP client: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
	})

	return session
}

// callScanTool invokes scan_vulnerable_dependencies over the MCP protocol and returns the text response.
func callScanTool(t *testing.T, session *mcp.ClientSession, paths, ignoreGlobs []string, recursive bool) (string, error) {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "scan_vulnerable_dependencies",
		Arguments: map[string]any{
			"paths":                paths,
			"ignore_glob_patterns": ignoreGlobs,
			"recursive":            recursive,
		},
	})
	if err != nil {
		return "", err
	}
	if len(res.Content) == 0 {
		t.Fatal("scan_vulnerable_dependencies returned empty content")
	}
	textContent, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", res.Content[0])
	}
	if res.IsError {
		return filepath.ToSlash(textContent.Text), os.ErrInvalid
	}

	return filepath.ToSlash(textContent.Text), nil
}

// TestMCP_ScanVulnerableDependencies_IgnoreGlobPatterns verifies end-to-end MCP tool behavior
// for empty baseline vs subtree/file glob exclusions.
//
//nolint:paralleltest // DoScan mutates global logger and color settings
func TestMCP_ScanVulnerableDependencies_IgnoreGlobPatterns(t *testing.T) {
	baseDir, rootLock, excludedLock := createTwoSubtreeFixture(t, "excluded")
	session := connectInMemoryMCP(t)

	rootSlash := filepath.ToSlash(rootLock)
	excludedSlash := filepath.ToSlash(excludedLock)

	t.Run("EmptyIgnoreGlobPatternsIncludesBoth", func(t *testing.T) {
		output, err := callScanTool(t, session, []string{baseDir}, []string{}, true)
		if err != nil {
			t.Fatalf("unexpected error on baseline scan: %v (output: %s)", err, output)
		}
		if !strings.Contains(output, rootSlash) {
			t.Errorf("baseline output missing root lockfile %q:\n%s", rootSlash, output)
		}
		if !strings.Contains(output, excludedSlash) {
			t.Errorf("baseline output missing excluded lockfile %q:\n%s", excludedSlash, output)
		}
	})

	patterns := []struct {
		name    string
		pattern string
	}{
		{name: "DoublestarExcludedSubtree", pattern: "**/excluded/**"},
		{name: "RelativeExcludedSubtree", pattern: "excluded/**"},
		{name: "DirectoryNamePattern", pattern: "**/excluded"},
		{name: "SpecificFilePattern", pattern: "excluded/package-lock.json"},
	}

	for _, tc := range patterns {
		t.Run(tc.name, func(t *testing.T) {
			output, err := callScanTool(t, session, []string{baseDir}, []string{tc.pattern}, true)
			if err != nil {
				t.Fatalf("unexpected error for pattern %q: %v (output: %s)", tc.pattern, err, output)
			}
			if !strings.Contains(output, rootSlash) {
				t.Errorf("pattern %q unexpectedly excluded root lockfile %q:\n%s", tc.pattern, rootSlash, output)
			}
			if strings.Contains(output, excludedSlash) {
				t.Errorf("pattern %q failed to exclude %q:\n%s", tc.pattern, excludedSlash, output)
			}
		})
	}
}

// TestMCP_ScanVulnerableDependencies_ChildSubtreeAndInvalidGlob verifies child/** exclusion and invalid glob rejection.
//
//nolint:paralleltest // DoScan mutates global logger and color settings
func TestMCP_ScanVulnerableDependencies_ChildSubtreeAndInvalidGlob(t *testing.T) {
	baseDir, rootLock, childLock := createTwoSubtreeFixture(t, "child")
	session := connectInMemoryMCP(t)

	rootSlash := filepath.ToSlash(rootLock)
	childSlash := filepath.ToSlash(childLock)

	for _, pat := range []string{"**/child/**", "child/**"} {
		output, err := callScanTool(t, session, []string{baseDir}, []string{pat}, true)
		if err != nil {
			t.Fatalf("unexpected error for pattern %q: %v", pat, err)
		}
		if !strings.Contains(output, rootSlash) {
			t.Errorf("pattern %q missing root lockfile %q:\n%s", pat, rootSlash, output)
		}
		if strings.Contains(output, childSlash) {
			t.Errorf("pattern %q did not exclude child lockfile %q:\n%s", pat, childSlash, output)
		}
	}

	_, err := callScanTool(t, session, []string{baseDir}, []string{"["}, true)
	if err == nil {
		t.Errorf("expected error for invalid glob pattern '['")
	}

	nonRecOut, err := callScanTool(t, session, []string{baseDir}, []string{"**/child/**"}, false)
	if err != nil {
		t.Fatalf("unexpected error for non-recursive scan: %v", err)
	}
	if !strings.Contains(nonRecOut, rootSlash) {
		t.Errorf("non-recursive scan missing root lockfile %q:\n%s", rootSlash, nonRecOut)
	}
	if strings.Contains(nonRecOut, childSlash) {
		t.Errorf("non-recursive scan unexpectedly included child lockfile %q:\n%s", childSlash, nonRecOut)
	}
}

// TestIgnoreFilter_Unit exercises directory, relative file, direct file, and post-scan filtering rules.
func TestIgnoreFilter_Unit(t *testing.T) {
	t.Parallel()
	baseDir, rootLock, childLock := createTwoSubtreeFixture(t, "child")

	tests := []struct {
		name            string
		patterns        []string
		wantRootIgnored bool
		wantChildDirIgn bool
		wantChildFilIgn bool
		wantErr         bool
	}{
		{
			name:     "empty_patterns",
			patterns: nil,
		},
		{
			name:            "doublestar_child_subtree",
			patterns:        []string{"**/child/**"},
			wantChildDirIgn: true,
			wantChildFilIgn: true,
		},
		{
			name:            "relative_child_subtree",
			patterns:        []string{"child/**"},
			wantChildDirIgn: true,
			wantChildFilIgn: true,
		},
		{
			name:            "trailing_slash_directory",
			patterns:        []string{"./child/"},
			wantChildDirIgn: true,
			wantChildFilIgn: true,
		},
		{
			name:            "file_level_glob_only",
			patterns:        []string{"child/package-lock.json"},
			wantChildDirIgn: false,
			wantChildFilIgn: true,
		},
		{
			name:            "all_package_lock_files",
			patterns:        []string{"**/package-lock.json"},
			wantRootIgnored: true,
			wantChildFilIgn: true,
		},
		{
			name:     "invalid_glob_syntax",
			patterns: []string{"[unclosed"},
			wantErr:  true,
		},
	}

	rootSlash := filepath.ToSlash(filepath.Clean(baseDir))
	childDirSlash := filepath.ToSlash(filepath.Join(baseDir, "child"))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			filter, err := newIgnoreFilter(tc.patterns, []string{baseDir})
			if (err != nil) != tc.wantErr {
				t.Fatalf("newIgnoreFilter(%v) error = %v, wantErr %v", tc.patterns, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			if got := filter.matchesDir(rootSlash, childDirSlash); got != tc.wantChildDirIgn {
				t.Errorf("matchesDir(child) = %v, want %v", got, tc.wantChildDirIgn)
			}
			if got := filter.matchesSourcePath(models.SourceInfo{Path: rootLock, Type: models.SourceTypeProjectPackage}); got != tc.wantRootIgnored {
				t.Errorf("matchesSourcePath(rootLock) = %v, want %v", got, tc.wantRootIgnored)
			}
			if got := filter.matchesSourcePath(models.SourceInfo{Path: childLock, Type: models.SourceTypeProjectPackage}); got != tc.wantChildFilIgn {
				t.Errorf("matchesSourcePath(childLock) = %v, want %v", got, tc.wantChildFilIgn)
			}
		})
	}
}

// TestFilterScanResults_PostFilterClearsActionableVulns verifies post-scan filtering and actionable check.
func TestFilterScanResults_PostFilterClearsActionableVulns(t *testing.T) {
	t.Parallel()
	baseDir, rootLock, childLock := createTwoSubtreeFixture(t, "excluded")
	filter, err := newIgnoreFilter([]string{"excluded/package-lock.json"}, []string{baseDir})
	if err != nil {
		t.Fatalf("newIgnoreFilter failed: %v", err)
	}

	results := models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{Path: filepath.ToSlash(rootLock), Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{
					{
						Package:         models.PackageInfo{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
						Vulnerabilities: []*osvschema.Vulnerability{{Id: "GHSA-root-1"}},
						Groups:          []models.GroupInfo{{IDs: []string{"GHSA-root-1"}}},
					},
				},
			},
			{
				Source: models.SourceInfo{Path: filepath.ToSlash(childLock), Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{
					{
						Package:         models.PackageInfo{Name: "minimist", Version: "1.2.0", Ecosystem: "npm"},
						Vulnerabilities: []*osvschema.Vulnerability{{Id: "GHSA-excluded-1"}},
						Groups:          []models.GroupInfo{{IDs: []string{"GHSA-excluded-1"}}},
					},
				},
			},
		},
	}

	filterScanResults(&results, filter)
	if len(results.Results) != 1 || results.Results[0].Source.Path != filepath.ToSlash(rootLock) {
		t.Fatalf("expected only rootLock remaining, got %+v", results.Results)
	}
	if !hasActionableVulns(&results) {
		t.Errorf("expected actionable vulns to remain true for rootLock")
	}

	allFilter, err := newIgnoreFilter([]string{"**/package-lock.json"}, []string{baseDir})
	if err != nil {
		t.Fatalf("newIgnoreFilter failed: %v", err)
	}
	filterScanResults(&results, allFilter)
	if hasActionableVulns(&results) {
		t.Errorf("expected no actionable vulns after excluding all sources")
	}

	_, _, allExcluded, prepErr := allFilter.prepareScanTargets([]string{childLock}, false)
	if prepErr != nil || !allExcluded {
		t.Errorf("expected direct file target to be marked allExcluded, got allExcluded=%v err=%v", allExcluded, prepErr)
	}

	_, _, err = handleScan(context.Background(), nil, &scanVulnerableDependenciesInput{
		Paths:              []string{childLock},
		IgnoreGlobPatterns: []string{"**/package-lock.json"},
	})
	if err == nil {
		t.Errorf("expected ErrNoPackagesFound when all direct input paths are excluded")
	}
}
