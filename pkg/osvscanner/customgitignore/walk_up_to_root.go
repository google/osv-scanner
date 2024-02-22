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

func parseGitIgnores(path string, recursive bool) (ps []gitignore.Pattern, repoRootPath string, err error) {
	// We need to parse .gitignore files from the root of the git repo to correctly identify ignored files
	var fs billy.Filesystem
	var ps, newPs []gitignore.Pattern

	// Normalise to path (or directory containing path if it's a file)
	path, err = getNormalisedDir(path)
	if err != nil {
		return nil, "", err
	}

	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil && !errors.Is(err, git.ErrRepositoryNotExists) {
		return ps, "", err
	}

	// not in a git repo; do not read .gitignore files
	// (and ignore recursive setting)
	if !errors.Is(err, git.ErrRepositoryNotExists) {
		return ps, path, nil
	}

	// inside a git repo

	repoRootPath, err = getRepoRootPath(repo)
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

	// Read parent dirs

	// read the per-repo info/exclude file
	newPs, err = readIgnoreFile(fs, []string{"."}, infoExcludeFile)
	if err != nil {
		return ps, "", err
	}
	ps = append(ps, newPs...)

	// Read parent's dirs up to git-root
	//
	if pathAbs != repoRootPath {
		newPs, err = readIgnoreFilesFromParents(fs, pathRel, repoRootPath)
		ps = append(ps, newPs...)
	}

	// Read children's subdirs
	//
	switch {
	case recursive:
		// Read subdirs, recursively
		ps, err = readPatterns(fs, toGoGitPath(pathRel), ps)

	default: // !recursive
		// only read single .gitignore file in this dir
		newPs, err = readIgnoreFile(fs, toGoGitPath(pathRel), gitignoreFile)
		ps = append(ps, newPs...)
	}
}

// Recursively walk up the the directory tree processing .gitignore files as we go.
// Once we reach the git-root dir, process it but don't recurse any further.
func readIgnoreFilesFromParents(fs billy.Filesystem, pathRel string, pathGitRoot string) (returnPs []gitignore.Pattern, err error) {
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

	switch {
	case pathAbs == pathGitRoot:
		// Don't recurse any further
		return ps, nil

	default:
		// continue recursing up tree
		newPs, err = readIgnoreFilesFromParents(fs, pathRel, pathGitRoot)
		if err != nil {
			return ps, err
		}
		ps = append(ps, newPs...)

		return ps, nil
	}
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
func toGoGitPath(path string) (pathSlice []string) {
	return strings.Split(path, string(os.PathSeparator))
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
func isDir(path string) (b bool, err error) {
	finfo, err := os.Stat(path)
	switch {
	case err != nil:
		return
	case finfo.IsDir():
		return true, nil
	default:
		return false, nil
	}
}

// ---------------- MAYBE ----------------

// - parsing file:
// 	- find the file's dir and then run the following rules...
//
// - parsing dir at the root of a git-repo
// 	- with recursive flag:
// 		- read all .gitignore files in repo
// 		- read .git/info/exclude for repo
// 	- without flag:
// 		- read .gitignore files in repo-root
// 		- read .git/info/exclude for repo
//
// - parsing dir within, a git-repo
// 	- with recursive flag:
// 		- read .gitignore in start dir
// 		- read all .gitignore files in child-dirs
// 		- read all .gitignore files in parent dirs up to and including repo-root
// 			(ie only dirs that are an ancestor)
// 		- read .git/info/exclude for repo
//
// 	- without flag:
// 		- read .gitignore in start dir
// 		- read all .gitignore files in parent dirs up to and including repo-root
// 			(ie only dirs that are an ancestor)
// 		- read .git/info/exclude for repo
//
// - parsing a plain dir: .gitignore files are ignored
//
// - (In all cases any dirs matched by a .gitignore that was read are skipped, including reading .gitignore files, and any matching files are ignored)

// ---------------- REMOVE ----------------

// // Make sure path does't have a trailing slash (os.PathSeparator )
// func removeTrailingSeparator(path string) string {
// 	l := len(path)
// 	if path[l-1] == os.PathSeparator {
// 		return path[:l-1] // /this/ -> this
// 	} else {
// 		return path // /this -> /this
// 	}
// }

// func readPatternsWithParents(fs billy.Filesystem, path string, ps []gitignore.Pattern) (returnPs []gitignore.Pattern, err error) {
// }

// func parseGitIgnoreForGitRoot(path string, recursive bool) (ps []gitignore.Pattern, repoRootPath string, err error) {
// }

// func parseGitIgnoreForGitMidTree(path string, recursive bool) (ps []gitignore.Pattern, repoRootPath string, err error) {
// }
