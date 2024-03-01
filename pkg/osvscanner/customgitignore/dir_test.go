package customgitignore_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scanner/pkg/osvscanner/customgitignore"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

func TestRecursivelyParsingGitignoreFilesFromIgnoredDir(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting at
	// the top of the tree at ./dir_a/dir_b
	start := filepath.Join(gitRepo, "dir_a", "dir_b")

	// Read this dir-tree using customgitignore, starting at the root
	patterns, _, err := customgitignore.ParseGitIgnores(start, true)
	if err != nil {
		t.Errorf("could not read gitignore patterns for test: %v", err)
	}

	var hasMatch bool

	// expect ./dir_a/dir_b/.gitignore to be processed
	//
	// Normally the `dir_a/dir_b/.gitignore` entry in
	// REPO_ROOT/.gitignore would stop this .gitignore from being
	// processed, but it's read because the file has been explicitly
	// supplied from the command-line.
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "dir_b", "DIR_B_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching dir_a/dir_b/DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore")
	}

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

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf(	"Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
							"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestNonRecursivelyParsingGitignoreFilesFromIgnoredDir(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting at
	// the top of the tree at ./dir_a/dir_b
	start := filepath.Join(gitRepo, "dir_a", "dir_b")

	// Read this dir-tree using customgitignore, starting at the root
	patterns, _, err := customgitignore.ParseGitIgnores(start, false)
	if err != nil {
		t.Errorf("could not read gitignore patterns for test: %v", err)
	}

	var hasMatch bool

	// expect ./dir_a/dir_b/.gitignore to be processed
	//
	// Normally the `dir_a/dir_b/.gitignore` entry in
	// REPO_ROOT/.gitignore would stop this .gitignore from being
	// processed, but it's read because the file has been explicitly
	// supplied from the command-line.
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "dir_b", "DIR_B_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching dir_a/dir_b/DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore")
	}

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

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf(	"Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
							"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestRecursivelyParsingGitignoreFilesFromMidTree(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting midway
	// up the tree at ./dir_a
	start := filepath.Join(gitRepo, "dir_a")
	patterns, _, err := customgitignore.ParseGitIgnores(start, true)
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

	// expect ./dir_a/parallel_b/.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "parallel_b", "PARALLEL_B_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching dir_a/parallel_b/PARALLEL_B_GITIGNORE from ./dir_a/parallel_b/.gitignore")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_B_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
			"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./parallel_a/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_A_GITIGNORE") {
		t.Fatalf("Expected not to find pattern matching PARALLEL_A_GITIGNORE from ./parallel_a/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestNonRecursivelyParsingGitignoreFilesFromMidTree(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting midway
	// up the tree at ./dir_a
	start := filepath.Join(gitRepo, "dir_a")
	patterns, _, err := customgitignore.ParseGitIgnores(start, false)
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

	// expect ./dir_a/parallel_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_B_GITIGNORE") {
		t.Errorf("Expected not to find a pattern matching dir_a/parallel_b/PARALLEL_B_GITIGNORE from ./dir_a/parallel_b/.gitignore" +
			"because parsing isn't recursive")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_B_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
			"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./parallel_a/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_A_GITIGNORE") {
		t.Fatalf("Expected not to find pattern matching PARALLEL_A_GITIGNORE from ./parallel_a/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestRecursivelyParsingGitignoreFilesFromMidTreeFile(t *testing.T) {
	t.Parallel()

	// expect this to be the same as TestNonRecursivelyParsingGitignoreFilesFromMidTree
	//   because the a_file is inside the that tests start-dir

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting midway
	// up the tree at ./dir_a
	start := filepath.Join(gitRepo, "dir_a", "a_file")
	patterns, _, err := customgitignore.ParseGitIgnores(start, true)
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

	// expect ./dir_a/parallel_b/.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "parallel_b", "PARALLEL_B_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching dir_a/parallel_b/PARALLEL_B_GITIGNORE from ./dir_a/parallel_b/.gitignore")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_B_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
			"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./parallel_a/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_A_GITIGNORE") {
		t.Fatalf("Expected not to find pattern matching PARALLEL_A_GITIGNORE from ./parallel_a/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestNonRecursivelyParsingGitignoreFilesFromMidTreeFile(t *testing.T) {
	t.Parallel()

	// expect this to be have the same results as TestNonRecursivelyParsingGitignoreFilesFromMidTree
	//   because the a_file is inside the that tests start-dir

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting midway
	// up the tree at ./dir_a
	start := filepath.Join(gitRepo, "dir_a", "a_file")
	patterns, _, err := customgitignore.ParseGitIgnores(start, false)
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

	// expect ./dir_a/parallel_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_B_GITIGNORE") {
		t.Errorf("Expected not to find a pattern matching dir_a/parallel_b/PARALLEL_B_GITIGNORE from ./dir_a/parallel_b/.gitignore" +
			"because parsing isn't recursive")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_B_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
			"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./parallel_a/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_A_GITIGNORE") {
		t.Fatalf("Expected not to find pattern matching PARALLEL_A_GITIGNORE from ./parallel_a/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestRecursivelyParsingGitignoreFilesFromRoot(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting at the root
	patterns, _, err := customgitignore.ParseGitIgnores(gitRepo, true)
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

	// expect ./parallel_a/.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "parallel_a", "PARALLEL_A_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Errorf("Expected to find a pattern matching parallel_a/PARALLEL_A_GITIGNORE from ./dir_a/.gitignore")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_B_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
			"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func TestNonRecursivelyParsingGitignoreFilesFromRoot(t *testing.T) {
	t.Parallel()

	// Create a specific git repo with .gitignore files
	gitRepo := setupGitRepo(t)

	// Read this dir-tree using customgitignore, starting at the root
	patterns, _, err := customgitignore.ParseGitIgnores(gitRepo, false)
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

	// expect ./dir_a/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_A_GITIGNORE") {
		t.Errorf("Expected to find a pattern matching dir_a/DIR_A_GITIGNORE from ./dir_a/.gitignore")
	}

	// expect ./parallel_a/.gitignore to be skipped over
	if hasPatternContaining(patterns, "PARALLEL_A_GITIGNORE") {
		t.Errorf("Expected to find a pattern matching parallel_a/PARALLEL_A_GITIGNORE from ./dir_a/.gitignore")
	}

	// expect ./dir_a/dir_b/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_B_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
			"dir_b should have been ignored by a rule in repository-root .gitignore")
	}

	// expect ./dir_a/dir_b/dir_c/.gitignore to be skipped over
	if hasPatternContaining(patterns, "DIR_C_GITIGNORE") {
		t.Errorf("Expected not to find pattern matching DIR_C_GITIGNORE from ./dir_a/dir_b/dir_c/.gitignore; " +
			"because it's parent dir_b should have been ignored by a rule in repository-root .gitignore")
	}
}

func setupGitRepo(t *testing.T) string {
	t.Helper()

	// A unique tempdir for local funcs to create a git repo inside
	gitRepo := filepath.Join(t.TempDir(), "git_repo")

	var allPaths string

	allPaths = filepath.Join(gitRepo, filepath.FromSlash(".git/info/"))
	if err := os.MkdirAll(allPaths, 0755); err != nil {
		t.Errorf("could not create paths for test: %v", err)
	}

	// create directory tree within tempdir
	allPaths = filepath.Join(gitRepo, filepath.FromSlash("dir_a/dir_b/dir_c"))
	if err := os.MkdirAll(allPaths, 0755); err != nil {
		t.Errorf("could not create paths for test: %v", err)
	}

	allPaths = filepath.Join(gitRepo, filepath.FromSlash("dir_a/parallel_b/"))
	if err := os.MkdirAll(allPaths, 0755); err != nil {
		t.Errorf("could not create paths for test: %v", err)
	}

	allPaths = filepath.Join(gitRepo, "parallel_a/")
	if err := os.MkdirAll(filepath.FromSlash(allPaths), 0755); err != nil {
		t.Fatalf("could not create paths for test: %v", err)
	}

	// initialise a git repo
	if _, err := git.PlainInit(gitRepo, false); err != nil {
		t.Errorf("could not initialise git repot for test: %v", err)
	}

	// add .gitignore files within the tree
	writeGitignore(t, gitRepo, filepath.FromSlash(".git/info/exclude"), "REPO_EXCLUDE_FILE")
	writeGitignore(t, gitRepo, filepath.FromSlash(".gitignore"), "ROOT_GITIGNORE\n"+"/dir_a/dir_b")
	writeGitignore(t, gitRepo, filepath.FromSlash("dir_a/.gitignore"), "DIR_A_GITIGNORE")
	writeGitignore(t, gitRepo, filepath.FromSlash("dir_a/dir_b/.gitignore"), "DIR_B_GITIGNORE")
	writeGitignore(t, gitRepo, filepath.FromSlash("dir_a/dir_b/dir_c/.gitignore"), "DIR_C_GITIGNORE")
	writeGitignore(t, gitRepo, filepath.FromSlash("dir_a/parallel_b/.gitignore"), "PARALLEL_B_GITIGNORE")
	writeGitignore(t, gitRepo, filepath.FromSlash("parallel_a/.gitignore"), "PARALLEL_A_GITIGNORE")

	// Create an everyday one (not actually a git-ignore file)
	writeGitignore(t, gitRepo, filepath.FromSlash("dir_a/a_file"), "A_FILE")

	return gitRepo
}

func writeGitignore(t *testing.T, gitRepo, f, s string) {
	t.Helper()

	f = filepath.Join(gitRepo, f)
	if err := os.WriteFile(f, []byte(s), 0600); err != nil {
		t.Errorf("could not write file for test: %v", err)
	}
}


// hasPatternContaining checks whether any of the gitignore.Pattern-s
// in gip contain a `pattern` field with the string `test` in it.
// For why see patternContains()
func hasPatternContaining(gips []gitignore.Pattern, test string) bool {
	for _, gip := range gips {
		if patternContains(gip, test) {
			return true
		}
	}

	return false
}

// Hack to test if gip.pattern == []string{"TEST_STRING"}
//
// This is necessary because gitignore.Pattern.pattern is
// non-exported.
//
// This matches against the return value from fmt.Sprintf
// with %#v, which means it may trip up on complicated or
// user supplied strings.
//
// By why can't we just test something like
// p.Match([]string{".", "dir_a", "DIR_A_GITIGNORE"}, false) != gitignore.Exclude
// instead ?
//
// ... because the changes in customgitignore adjust the
// implementation details of the upstream packge so that
// it doesn't read .gitingore files from ignored dirs.
// This means that before _and_ after the change p.Match()
// will return false.
func patternContains(gip gitignore.Pattern, test string) bool {
	summary := fmt.Sprintf("%#v", gip)
	actualTest := fmt.Sprintf("pattern:[]string{\"%s\"}", test)

	return strings.Contains(summary, actualTest)
}