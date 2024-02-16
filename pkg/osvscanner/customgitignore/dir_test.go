// TODO: check if there's a way to make this: `package customgitignore` instead
package customgitignore_test

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/google/osv-scanner/pkg/osvscanner/customgitignore"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

func TestGitignoreFilesFromMidTree(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting midway
	// up the tree at ./dir_a
	gitRepo = filepath.Join(gitRepo, "dir_a")
	fs := osfs.New(gitRepo)
	patterns, err := customgitignore.ReadPatterns(fs, []string{"."})
	if err != nil {
		t.Errorf("could not read gitignore patterns for test: %v", err)
	}

	var hasMatch bool

	// expect ./.git/info/exclude to be processed, by backtracking up the tree
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "REPO_EXCLUDE_FILE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching REPO_EXCLUDE_FILE from ./.git/info/exclude ")
	}

	// expect ./.gitignore to be processed (by backtracking up the tree)
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "ROOT_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching ROOT_GITIGNORE from repository-root .gitignore")
	}

	// expect ./dir_a/.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "DIR_A_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching dir_a/DIR_A_GITIGNORE from ./dir_a/.gitignore")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	//
	// I want to test for the lack of a GITIGNORE_B match,
	// to show that dir_a/dir_b/.gitignore wasn't processed.
	// Annoyingly the `dir_a/dir_b` pattern from .GITIGNORE_ROOT
	// prevents this.
	// Instead I'm doing dubious `reflect` hackery to get
	// access to the unxported `Pattern.pattern` field
	for _, pattern := range patterns {
		// dubious `reflect` hackery means: slice := pattern.pattern
		fv := reflect.ValueOf(pattern).Elem().FieldByName("pattern")

		// tests if pattern.patter == []string{"DIR_B_GITIGNORE"}
		if fv.Len() == 1 && fv.Index(0).String() == "DIR_B_GITIGNORE" {
			t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
				"dir_b should have been ignored by a rule in repository-root .gitignore")
		}
	}
}

func TestGitignoreFilesFromRoot(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting at the root
	fs := osfs.New(gitRepo)
	patterns, err := customgitignore.ReadPatterns(fs, []string{"."})
	if err != nil {
		t.Errorf("could not read gitignore patterns for test: %v", err)
	}

	var hasMatch bool

	// expect ./.git/info/exclude to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "REPO_EXCLUDE_FILE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching REPO_EXCLUDE_FILE from ./.git/info/exclude ")
	}

	// expect ./.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "ROOT_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching ROOT_GITIGNORE from repository-root .gitignore")
	}

	// expect ./dir_a/.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "DIR_A_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching dir_a/DIR_A_GITIGNORE from ./dir_a/.gitignore")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	//
	// I want to test for the lack of a GITIGNORE_B match,
	// to show that dir_a/dir_b/.gitignore wasn't processed.
	// Annoyingly the `dir_a/dir_b` pattern from .GITIGNORE_ROOT
	// prevents this.
	// Instead I'm doing dubious `reflect` hackery to get
	// access to the unxported `Pattern.pattern` field
	for _, pattern := range patterns {
		// dubious `reflect` hackery means: slice := pattern.pattern
		fv := reflect.ValueOf(pattern).Elem().FieldByName("pattern")

		// tests if pattern.patter == []string{"DIR_B_GITIGNORE"}
		if fv.Len() == 1 && fv.Index(0).String() == "DIR_B_GITIGNORE" {
			t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
				"dir_b should have been ignored by a rule in repository-root .gitignore")
		}
	}
}

func setupGitRepo(t *testing.T) string {
	t.Helper()

	// A unique tempdir for local funcs to create a git repo inside
	gitRepo := path.Join(t.TempDir(), "git_repo")

	// create directory tree within tempdir
	allPaths := path.Join(gitRepo, "dir_a/dir_b")
	if err := os.MkdirAll(filepath.FromSlash(allPaths), 0755); err != nil {
		t.Errorf("could not create paths for test: %v", err)
	}

	allPaths = path.Join(gitRepo, ".git/info/")
	if err := os.MkdirAll(filepath.FromSlash(allPaths), 0755); err != nil {
		t.Errorf("could not create paths for test: %v", err)
	}

	// initialise a git repo
	if _, err := git.PlainInit(filepath.FromSlash(gitRepo), false); err != nil {
		t.Errorf("could not initialise git repot for test: %v", err)
	}

	// add .gitignore files within the tree
	writeGitignore(t, gitRepo, ".git/info/exclude", "REPO_EXCLUDE_FILE")
	writeGitignore(t, gitRepo, ".gitignore", "ROOT_GITIGNORE\n"+"/dir_a/dir_b")
	writeGitignore(t, gitRepo, "dir_a/.gitignore", "DIR_A_GITIGNORE")
	writeGitignore(t, gitRepo, "dir_a/dir_b/.gitignore", "DIR_B_GITIGNORE")

	return gitRepo
}

func writeGitignore(t *testing.T, gitRepo, f, s string) {
	t.Helper()

	f = path.Join(gitRepo, f)
	if err := os.WriteFile(filepath.FromSlash(f), []byte(s), 0600); err != nil {
		t.Errorf("could not write file for test: %v", err)
	}
}

// --- NOTES BEGIN ---

// // to pick up:
//
// 	f = filepath.Join(tDir, "git_repo/.gitignore")
//
// 	f = filepath.Join(tDir, "git_repo/dir_a/.gitignore")
// 	f = filepath.Join(tDir, "git_repo/dir_a/dir_b/.gitignore")
//
// // but not
//
// 	f = filepath.Join(tDir, "git_repo/dir_a/dir_b/subdir/.gitignore")
// 	f = filepath.Join(tDir, "git_repo/not_in_original_path/.gitignore")
//
// // Is that about right?