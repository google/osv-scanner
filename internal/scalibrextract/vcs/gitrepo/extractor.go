package gitrepo

import (
	"context"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor extracts git repository hashes including submodule hashes.
// This extractor will not return an error, and will just return no results if we fail to extract
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

func getCommitSHA(repo *git.Repository) (string, error) {
	head, err := repo.Head()
	if err != nil {
		return "", err
	}

	return head.Hash().String(), nil
}

func getSubmodules(repo *git.Repository) (submodules []*git.SubmoduleStatus, err error) {
	worktree, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	ss, err := worktree.Submodules()
	if err != nil {
		return nil, err
	}
	for _, s := range ss {
		status, err := s.Status()
		if err != nil {
			continue
		}
		submodules = append(submodules, status)
	}

	return submodules, nil
}

func createCommitQueryInventory(commit string, path string) *extractor.Inventory {
	return &extractor.Inventory{
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: commit,
		},
		Locations: []string{path},
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return "vcs/gitrepo" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for .package-lock.json files under node_modules
func (e Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	if filepath.Base(fapi.Path()) != ".git" {
		return false
	}

	// Stat costs performance, so perform it after the name check
	stat, err := fapi.Stat()
	if err != nil {
		return false
	}

	return stat.IsDir()
}

// Extract extracts packages from yarn.lock files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	// Assume this is fully on a real filesystem
	// TODO: Make this support virtual filesystems
	repo, err := git.PlainOpen(path.Join(input.Root, filepath.Dir(input.Path)))
	if err != nil {
		return nil, err
	}

	//nolint:prealloc // Not sure how many there will be in advance.
	var packages []*extractor.Inventory

	commitSHA, err := getCommitSHA(repo)

	// If error is not nil, then ignore this and continue, as it is not fatal.
	// The error could be because there are no commits in the repository
	if err == nil {
		packages = append(packages, createCommitQueryInventory(commitSHA, input.Path))
	}

	// If we can't get submodules, just return with what we have.
	submodules, err := getSubmodules(repo)
	if err != nil {
		return packages, err
	}

	for _, s := range submodules {
		// r.Infof("Scanning submodule %s at commit %s\n", s.Path, s.Expected.String())
		packages = append(packages, createCommitQueryInventory(s.Expected.String(), path.Join(input.Path, s.Path)))
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(_ *extractor.Inventory) *purl.PackageURL {
	return nil
}

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return ""
}

var _ filesystem.Extractor = Extractor{}
