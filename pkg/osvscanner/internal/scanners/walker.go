package scanners

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scanner/v2/internal/customgitignore"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/scalibrextract"
)

// ScanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
//
// TODO(V2 Models): pomExtractor is temporary until V2 Models
func ScanDir(dir string, recursive bool, useGitIgnore bool, extractorsToUse []filesystem.Extractor) ([]*extractor.Package, error) {
	var ignoreMatcher *gitIgnoreMatcher
	if useGitIgnore {
		var err error
		ignoreMatcher, err = parseGitIgnores(dir, recursive)
		if err != nil {
			if errors.Is(err, git.ErrRepositoryNotExists) {
				slog.Info("Not in a Git repository, ignoring .gitignores")
			} else {
				slog.Error(fmt.Sprintf("Unable to parse git ignores: %v", err))
			}
			useGitIgnore = false
		}
	}

	root := true

	var scannedInventories []*extractor.Package

	err := filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			slog.Info(fmt.Sprintf("Failed to walk %s: %v", path, err))
			return err
		}

		path, err = filepath.Abs(path)
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to walk path %s", err))
			return err
		}

		if useGitIgnore {
			match, err := ignoreMatcher.match(path, info.IsDir())
			if err != nil {
				slog.Info(fmt.Sprintf("Failed to resolve gitignore for %s: %v", path, err))
				// Don't skip if we can't parse now - potentially noisy for directories with lots of items
			} else if match {
				if root { // Don't silently skip if the argument file was ignored.
					slog.Error(path + " was not scanned because it is excluded by a .gitignore file. Use --no-ignore to scan it.")
				}
				if info.IsDir() {
					return filepath.SkipDir
				}

				return nil
			}
		}

		// -------- Perform scanning --------
		inventories, err := scalibrextract.ExtractWithExtractors(context.Background(), path, extractorsToUse)
		if err != nil && !errors.Is(err, scalibrextract.ErrExtractorNotFound) {
			slog.Error(fmt.Sprintf("Error during extraction: %s", err))
		}

		pkgCount := len(inventories)
		if pkgCount > 0 {
			// TODO(v2): Display the name of the extractor used here
			slog.Info(fmt.Sprintf(
				"Scanned %s file and found %d %s",
				path,
				pkgCount,
				output.Form(pkgCount, "package", "packages"),
			))
		}

		scannedInventories = append(scannedInventories, inventories...)

		// Optimisation to skip git repository .git dirs
		if info.IsDir() && info.Name() == ".git" {
			// Always skip git repository directories
			return filepath.SkipDir
		}

		if !root && !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		root = false

		return nil
	})

	return scannedInventories, err
}

type gitIgnoreMatcher struct {
	matcher  gitignore.Matcher
	repoPath string
}

// parseGitIgnores creates a gitIgnoreMatcher for the given directory.
// If no git repository exists, then git.ErrRepositoryNotExists is returned.
func parseGitIgnores(path string, recursive bool) (*gitIgnoreMatcher, error) {
	patterns, repoRootPath, err := customgitignore.ParseGitIgnores(path, recursive)
	if err != nil {
		return nil, err
	}

	matcher := gitignore.NewMatcher(patterns)

	return &gitIgnoreMatcher{matcher: matcher, repoPath: repoRootPath}, nil
}

// gitIgnoreMatcher.match will return true if the file/directory matches a gitignore entry
// i.e. true if it should be ignored
func (m *gitIgnoreMatcher) match(absPath string, isDir bool) (bool, error) {
	pathInGit, err := filepath.Rel(m.repoPath, absPath)
	if err != nil {
		return false, err
	}
	// must prepend "." to paths because of how gitignore.ReadPatterns interprets paths
	pathInGitSep := []string{"."}
	if pathInGit != "." { // don't make the path "./."
		pathInGitSep = append(pathInGitSep, strings.Split(pathInGit, string(filepath.Separator))...)
	}

	return m.matcher.Match(pathInGitSep, isDir), nil
}
