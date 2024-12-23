package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scanner/internal/customgitignore"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/scalibrextract"
	"github.com/google/osv-scanner/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/pkg/reporter"
)

// ScanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
//
// TODO(V2 Models): pomExtractor is temporary until V2 Models
func ScanDir(r reporter.Reporter, dir string, skipGit bool, recursive bool, useGitIgnore bool, pomExtractor filesystem.Extractor) ([]*extractor.Inventory, error) {
	var ignoreMatcher *gitIgnoreMatcher
	if useGitIgnore {
		var err error
		ignoreMatcher, err = parseGitIgnores(dir, recursive)
		if err != nil {
			r.Errorf("Unable to parse git ignores: %v\n", err)
			useGitIgnore = false
		}
	}

	root := true

	// Setup scan config
	relevantExtractors := []filesystem.Extractor{}
	if !skipGit {
		relevantExtractors = append(relevantExtractors, gitrepo.Extractor{})
	}
	relevantExtractors = append(relevantExtractors, lockfileExtractors...)
	relevantExtractors = append(relevantExtractors, SBOMExtractors...)
	if pomExtractor != nil {
		relevantExtractors = append(relevantExtractors, pomExtractor)
	} else {
		// Use the offline pomxml extractor if networking is unavailable
		relevantExtractors = append(relevantExtractors, pomxml.Extractor{})
	}

	var scannedInventories []*extractor.Inventory

	err := filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			r.Infof("Failed to walk %s: %v\n", path, err)
			return err
		}

		path, err = filepath.Abs(path)
		if err != nil {
			r.Errorf("Failed to walk path %s\n", err)
			return err
		}

		if useGitIgnore {
			match, err := ignoreMatcher.match(path, info.IsDir())
			if err != nil {
				r.Infof("Failed to resolve gitignore for %s: %v\n", path, err)
				// Don't skip if we can't parse now - potentially noisy for directories with lots of items
			} else if match {
				if root { // Don't silently skip if the argument file was ignored.
					r.Errorf("%s was not scanned because it is excluded by a .gitignore file. Use --no-ignore to scan it.\n", path)
				}
				if info.IsDir() {
					return filepath.SkipDir
				}

				return nil
			}
		}

		// -------- Perform scanning --------
		inventories, err := scalibrextract.ExtractWithExtractors(context.Background(), path, relevantExtractors)
		if err != nil && !errors.Is(err, scalibrextract.ErrExtractorNotFound) {
			r.Errorf("Error during extraction: %s\n", err)
		}

		pkgCount := len(inventories)
		if pkgCount > 0 {
			// TODO(v2): Display the name of the extractor used here
			r.Infof(
				"Scanned %s file and found %d %s\n",
				path,
				pkgCount,
				output.Form(pkgCount, "package", "packages"),
			)
		}

		scannedInventories = append(scannedInventories, inventories...)

		// Optimisation to skip git repository .git dirs
		if info.IsDir() && info.Name() == ".git" {
			// Always skip git repository directories
			return filepath.SkipDir
		}

		// TODO(V2): Reenable vendored libs scanning
		// if info.IsDir() && !compareOffline {
		// 	if _, ok := vendoredLibNames[strings.ToLower(filepath.Base(path))]; ok {
		// 		pkgs, err := ScanDirWithVendoredLibs(r, path)
		// 		if err != nil {
		// 			r.Infof("scan failed for dir containing vendored libs %s: %v\n", path, err)
		// 		}
		// 		scannedPackages = append(scannedPackages, pkgs...)
		// 	}
		// }

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
