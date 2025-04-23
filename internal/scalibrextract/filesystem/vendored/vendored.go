package vendored

import (
	"bytes"
	"context"
	"io"
	"slices"

	//nolint:gosec
	// md5 used to identify files, not for security purposes
	"crypto/md5"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"osv.dev/bindings/go/osvdev"
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

	fileExts = []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}
)

const (
	// Name is the unique name of this extractor.
	Name = "filesystem/vendored"
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
	OSVClient  *osvdev.OSVClient
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

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
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var packages []*extractor.Package

	results, err := e.queryDetermineVersions(ctx, input.Path, input.FS, e.ScanGitDir)
	if err != nil {
		return inventory.Inventory{}, err
	}

	if len(results.Matches) > 0 && results.Matches[0].Score > determineVersionThreshold {
		match := results.Matches[0]
		// r.Infof("Identified %s as %s at %s.\n", libPath, match.RepoInfo.Address, match.RepoInfo.Commit)
		packages = append(packages, &extractor.Package{
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: match.RepoInfo.Commit,
			},
			Locations: []string{input.Path},
		})
	}

	return inventory.Inventory{
		Packages: packages,
	}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(_ *extractor.Package) *purl.PackageURL {
	return nil
}

// Ecosystem returns an empty string as all inventories are commit hashes
func (e Extractor) Ecosystem(_ *extractor.Package) string {
	return ""
}

func (e Extractor) queryDetermineVersions(ctx context.Context, repoDir string, fsys scalibrfs.FS, scanGitDir bool) (*osvdev.DetermineVersionResponse, error) {
	var hashes []osvdev.DetermineVersionHash

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

		if !slices.Contains(fileExts, filepath.Ext(p)) {
			return nil
		}

		file, err := fsys.Open(p)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer(nil)
		_, err = io.Copy(buf, file)
		if err != nil {
			return err
		}
		hash := md5.Sum(buf.Bytes()) //nolint:gosec
		hashes = append(hashes, osvdev.DetermineVersionHash{
			Path: strings.ReplaceAll(p, repoDir, ""),
			Hash: hash[:],
		})
		if len(hashes) > maxDetermineVersionFiles {
			return errors.New("too many files to hash")
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed during hashing: %w", err)
	}

	result, err := e.OSVClient.ExperimentalDetermineVersion(ctx, &osvdev.DetermineVersionsRequest{
		Name:       filepath.Base(repoDir),
		FileHashes: hashes,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to determine versions: %w", err)
	}

	return result, nil
}

var _ filesystem.Extractor = Extractor{}
