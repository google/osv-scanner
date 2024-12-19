package vendored

import (
	"context"
	//nolint:gosec
	// md5 used to identify files, not for security purposes
	"crypto/md5"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/pkg/osv"
)

var (
	vendoredLibNames = map[string]struct{}{
		"3rdparty":    {},
		"dep":         {},
		"deps":        {},
		"thirdparty":  {},
		"third-party": {},
		"third_party": {},
		"libs":        {},
		"external":    {},
		"externals":   {},
		"vendor":      {},
		"vendored":    {},
	}
)

const (
	// This value may need to be tweaked, or be provided as a configurable flag.
	determineVersionThreshold = 0.15
	maxDetermineVersionFiles  = 10000
)

type Extractor struct {
	// ScanGitDir determines whether a vendored library with a git directory is scanned or not,
	// this is used to avoid duplicate results, once from git scanning, once from vendoredDir scanning
	ScanGitDir bool
	// TODO(v2): Client rework
	// determineVersionsClient
}

var _ filesystem.Extractor = Extractor{}

// Name of the extractor.
func (e Extractor) Name() string { return "filesystem/vendored" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for likely directories to contain vendored c/c++ code
func (e Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	// Check if parent directory is one of the vendoredLibName
	// Clean first before Dir call to avoid trailing slashes causing problems
	parentDir := filepath.Base(filepath.Dir(filepath.Clean(fapi.Path())))
	_, ok := vendoredLibNames[parentDir]
	if !ok {
		return false
	}

	// Stat costs performance, so perform it after the name check
	stat, err := fapi.Stat()
	if err != nil {
		return false
	}

	return stat.IsDir()
}

// Extract determines the most likely package version from the directory and returns them as
// commit hash inventory entries
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var packages []*extractor.Inventory

	// r.Infof("Scanning potential vendored dir: %s\n", libPath)
	// TODO: make this a goroutine to parallelize this operation
	results, err := queryDetermineVersions(input.Path, input.FS, e.ScanGitDir)
	if err != nil {
		return nil, err
	}

	if len(results.Matches) > 0 && results.Matches[0].Score > determineVersionThreshold {
		match := results.Matches[0]
		// r.Infof("Identified %s as %s at %s.\n", libPath, match.RepoInfo.Address, match.RepoInfo.Commit)
		packages = append(packages, &extractor.Inventory{
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: match.RepoInfo.Commit,
			},
			Locations: []string{input.Path},
		})
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(_ *extractor.Inventory) *purl.PackageURL {
	return nil
}

// Ecosystem returns an empty string as all inventories are commit hashes
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return ""
}

func queryDetermineVersions(repoDir string, fsys scalibrfs.FS, scanGitDir bool) (*osv.DetermineVersionResponse, error) {
	fileExts := []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}

	var hashes []osv.DetermineVersionHash

	err := fs.WalkDir(fsys, repoDir, func(p string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			if !scanGitDir {
				if _, err := fsys.Stat(filepath.Join(p, ".git")); err == nil {
					// Found a git repo, stop here as otherwise we may get duplicated
					// results with our regular git commit scanning.
					return filepath.SkipDir
				}
			}

			if _, ok := vendoredLibNames[strings.ToLower(d.Name())]; ok {
				// Ignore nested vendored libraries, as they can cause bad matches.
				return filepath.SkipDir
			}

			return nil
		}
		for _, ext := range fileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				hash := md5.Sum(buf) //nolint:gosec
				hashes = append(hashes, osv.DetermineVersionHash{
					Path: strings.ReplaceAll(p, repoDir, ""),
					Hash: hash[:],
				})
				if len(hashes) > maxDetermineVersionFiles {
					return errors.New("too many files to hash")
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed during hashing: %w", err)
	}

	result, err := osv.MakeDetermineVersionRequest(filepath.Base(repoDir), hashes)
	if err != nil {
		return nil, fmt.Errorf("failed to determine versions: %w", err)
	}

	return result, nil
}
