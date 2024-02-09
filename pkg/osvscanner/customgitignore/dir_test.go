// TODO: check if there's a way to make this: `package customgitignore` instead
package customgitignore_test

import (
	"testing"
	"os"
	"path"
	"path/filepath"
	"slices"
	"reflect"

	"github.com/google/osv-scanner/pkg/osvscanner/customgitignore"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)



var gitRepoMemo string

// A unique tempdir for local funcs to create a git repo inside
func gitRepo() string {
	if gitRepoMemo == "" {
		gitRepoMemo = path.Join(t.TempDir(), "git_repo")
	}

	return gitRepoMemo
}

func TestGitignoreFiles(t *testing.T) {
	// Create a specific git repo with .gitignore files
	setupGitRepo(t)

	// Read this dir-tree using customgitignore
	fs := osfs.New(gitRepo())
	patterns, err := customgitignore.ReadPatterns(fs, []string{"."})
	if err != nil {
		t.Fatalf("could not read gitignore patterns for test: %v", err)
	}

	var hasMatch bool

	// expect ./.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "ROOT_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Fatalf("Expected to find a pattern matching ROOT_GITIGNORE from repository-root .gitignore")
	}

	// expect ./dir_a/.gitignore to be processed
	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "DIR_A_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Fatalf("Expected to find a pattern matching dir_a/DIR_A_GITIGNORE from ./dir_a/.gitignore")
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
			t.Fatalf(	"Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
								"dir_b should have been ignored by a rule in repository-root .gitignore")
		}
	}
}

func setupGitRepo(t *testing.T) {
	// create directory tree within tempdir
  allPaths := path.Join(gitRepo(), "dir_a/dir_b")
	if err := os.MkdirAll(filepath.FromSlash(allPaths), 0755); err != nil {
		t.Fatalf("could not create paths for test: %v", err)
  }

	// initialise a git repo
	if _, err := git.PlainInit(filepath.FromSlash(gitRepo()), false); err != nil {
		t.Fatalf("could not initialise git repot for test: %v", err)
	}

	// add .gitignore files within the tree
	writeGitignore(t, ".gitignore", 						"ROOT_GITIGNORE\n" +
																							"/dir_a/dir_b")
	writeGitignore(t, "dir_a/.gitignore", 			"DIR_A_GITIGNORE")
	writeGitignore(t, "dir_a/dir_b/.gitignore", "DIR_B_GITIGNORE")
}

func writeGitignore(t *testing.T, iFile, text string) {
	iFile = path.Join(gitRepo(), iFile)
	if err := os.WriteFile(filepath.FromSlash(iFile), []byte(text), 0644); err != nil {
		t.Fatalf("could not write file for test: %v", err)
	}
}



	// --- NOTES BEGIN ---

	// if patterns_not_include_something {
	//		t.Fatalf("could not write file for test: %v", err)
	// }


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
