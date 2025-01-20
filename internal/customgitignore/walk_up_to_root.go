package customgitignore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// Takes a dir and processes .gitignore files from it.
//
// This uses go-git under the hood and returns a slice
// of go-git's gitignore.Pattern structs.
//
// Because this function finds the enclosing git repo, it
// returns that as its second argument, which may be
// `path`, or a parent of `path`, or "" if there's no
// enclosing git repo.
//
// Because it detects the root of any enclosing git repo
// if path doesn't exist the root, it returns this repoPath
// or "" if there is none.
//
// It also returns the path to the root of the git-repo,
// or "" if this path isn't within a git repo, allowing
// a caller to know how .gitignore files were parsed.
//
// The actual parsing is intended to be similar to how tools
// like rg work, but means that `path` may not necessarily be
// the root of a git repo, and can produces these parsing
// behaviours:
//
// `path` is a plain dir:
//
//   - .gitignore files are ignored
//
// `path` is a file:
//
//   - find the file's dir and then run the following rules...
//
// `path` is a dir at the root of a git-repo, with recursive flag:
//
//   - read all .gitignore files in repo
//   - read .git/info/exclude for repo
//
// `path` is a dir at the root of a git-repo, without recursive flag:
//
//   - only read .gitignore files in repo-root
//   - read .git/info/exclude for repo
//
// `path` is a dir within a git-repo, with recursive flag:
//
//   - read .gitignore in start dir
//   - read all .gitignore files in child-dirs
//   - read all .gitignore files in parent dirs up to and including repo-root
//     (but only dirs that are an ancestor)
//
// `path` is a dir within, a git-repo, without recursive flag:
//
//   - read .gitignore in start dir
//   - read all .gitignore files in parent dirs up to and including repo-root
//     (but only dirs that are an ancestor)
//   - read .git/info/exclude for repo
//
// NOTE: the dir you're passing in directly could be a dir that is ignored
// (targeted by a parent's .gitignore or the per-repo exclude file); in this
// case, the dir's .gitignore file is still processed, but not its sub-dirs.
//
// In all cases any dirs matched by a previously read
// .gitignore are skipped, unless it's the path (ie directly
// supplied by the user).
func ParseGitIgnores(path string, recursive bool) ([]gitignore.Pattern, string, error) {
	// We need to parse .gitignore files from the root of the git repo to correctly identify ignored files
	var fs billy.Filesystem
	var ps, newPs []gitignore.Pattern

	// Normalise to path (or directory containing path if it's a file)
	path, err := getNormalisedDir(path)
	if err != nil {
		return nil, "", err
	}

	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil && !errors.Is(err, git.ErrRepositoryNotExists) {
		return ps, "", err
	}

	// not in a git repo; do not read .gitignore files
	// (and ignore recursive setting)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return ps, "", nil
	}

	// inside a git repo

	repoRootPath, err := getRepoRootPath(repo)
	if err != nil {
		return ps, "", err
	}

	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return ps, "", err
	}

	// path WRT git-root
	pathRel, err := filepath.Rel(repoRootPath, pathAbs)
	if err != nil {
		return ps, "", err
	}

	fs = osfs.New(repoRootPath)

	// read the per-repo info/exclude file
	newPs, err = readIgnoreFile(fs, []string{"."}, infoExcludeFile)
	if err != nil && !os.IsNotExist(err) {
		return ps, "", err
	}
	ps = append(ps, newPs...)

	// Read parent's dirs up to git-root
	//
	if pathAbs != repoRootPath {
		newPs, err = readIgnoreFilesFromParents(fs, pathRel, repoRootPath)
		if err != nil && !os.IsNotExist(err) {
			return ps, "", err
		}
		ps = append(ps, newPs...)
	}

	// Read children's subdirs
	//
	if recursive {
		newPs, err = ReadPatternsIgnoringDirs(fs, toGoGitPath(pathRel), ps)
	} else {
		// only read single .gitignore file in this dir
		newPs, err = readIgnoreFile(fs, toGoGitPath(pathRel), gitignoreFile)
	}

	if err != nil && !os.IsNotExist(err) {
		return ps, "", err
	}

	ps = append(ps, newPs...)

	return ps, repoRootPath, nil
}

// Recursively walk up the directory tree processing .gitignore files as we go.
// Once we reach the git-root dir, process it but don't recurse any further.
func readIgnoreFilesFromParents(fs billy.Filesystem, pathRel string, pathGitRoot string) ([]gitignore.Pattern, error) {
	var ps []gitignore.Pattern

	// Recurse up the tree to path's parent
	pathRel = parentPath(pathRel)

	pathAbs := filepath.Join(pathGitRoot, pathRel)

	// read .gitignore
	newPs, err := readIgnoreFile(fs, toGoGitPath(pathRel), gitignoreFile)
	if err != nil {
		return ps, err
	}
	ps = append(ps, newPs...)

	if pathAbs == pathGitRoot {
		// Don't recurse any further
		return ps, nil
	}

	// continue recursing up tree
	newPs, err = readIgnoreFilesFromParents(fs, pathRel, pathGitRoot)
	if err != nil {
		return ps, err
	}
	ps = append(ps, newPs...)

	return ps, nil
}

// returns the path of the root of this repo (ie with the .git dir in it)
func getRepoRootPath(repo *git.Repository) (string, error) {
	tree, err := repo.Worktree()
	if err != nil {
		return "", err
	}

	root := tree.Filesystem.Root()
	root, err = filepath.Abs(root)

	return root, err
}

// return path (slice) for the parent of path (arg)
func parentPath(path string) string {
	// MAYBE: read and return '..', instead of getting the parent lexically
	//  so that we handle symlinks, and other FS-complexity
	return filepath.Dir(path)
}

// go-git uses a slice internally to represent paths.
// This func converts a slash separated path to this format.
// eg "/path/to/file" -> []string{"", "path", "to", "file"}
//
// This assumes slash-separated paths (eg paths.Join, as
// opposed to filepath.Join)
func toGoGitPath(path string) []string {
	dirPath := strings.Split(path, string(os.PathSeparator))
	if dirPath[0] != "." {
		dirPath = append([]string{"."}, dirPath...)
	}

	return dirPath
}

// Convert path directory without a trailing slash,
// letting you call filepath.Dir(p) on it.
//
// eg
//
// - /this/is/a/file -> /this/is/a
// - /this/is/a/dir/ -> /this/is/a/dir
// - /this/is/a/dir -> /this/is/a/dir
func getNormalisedDir(path string) (string, error) {
	checkIsDir, err := isDir(path)
	switch {
	case err != nil:
		return "", err
	case checkIsDir:
		return filepath.Clean(path), nil // remove any trailing slash separator
	default:
		return filepath.Dir(path), nil
	}
}

// Use file system operations to test for dir-y-ness
func isDir(path string) (bool, error) {
	finfo, err := os.Stat(path)
	switch {
	case err != nil:
		return false, err
	case finfo.IsDir():
		return true, nil
	default:
		return false, nil
	}
}
