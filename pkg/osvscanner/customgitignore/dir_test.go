// TODO: check if there's a way to make this: `package customgitignore` instead
package customgitignore_test

import (
	"fmt"
	"testing"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/pkg/osvscanner/customgitignore"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	// "github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

func TestBigBallOTest(t *testing.T) {
	// Vars for re-use: file, dir, text
	var f, d string
	var s string
	var err error

	// Create a test-local tempdir
	tDir := t.TempDir()

	// // Create a temporary dir to test out .git tree passing
	// tDir, err = os.MkdirTemp("", "customgitingore-*")
	// if err != nil {
	// 	t.Fatalf("could not create test directory: %v", err)
	// }

	// defer _ = function() {
	// 	os.RemoveAll(tDir)
	// }

	// create tree within tempdir
  allPaths := filepath.Join(tDir, "git_repo/dir_a/dir_b")
	err = os.MkdirAll(allPaths, 0755)
  if err != nil {
		t.Fatalf("could not create paths for test: %v", err)
  }

	// initialise .git repo
	d = filepath.Join(tDir, "git_repo/")
	_, err = git.PlainInit(d, false)
  if err != nil {
		t.Fatalf("could not initialise git repot for test: %v", err)
	}

	// create .gitignore files
	f = filepath.Join(tDir, "git_repo/.gitignore")
	s = "git_repo:.gitignore-file" + "\n" + "/dir_a/dir_b"
	s = ( "git_repo:.gitignore-file")
	err = os.WriteFile(f, []byte(s), 0644)
	if err != nil {
		t.Fatalf("could not write file for test: %v", err)
	}

	f = filepath.Join(tDir, "git_repo/dir_a/.gitignore")
	s = "git_repo:dir_a:.gitignore-file"
	err = os.WriteFile(f, []byte(s), 0644)
	if err != nil {
		t.Fatalf("could not write file for test: %v", err)
	}

	f = filepath.Join(tDir, "git_repo/dir_a/dir_b/.gitignore")
	s = "git_repo:dir_a:dir_b:.gitignore-file"
	err = os.WriteFile(f, []byte(s), 0644)
	if err != nil {
		t.Fatalf("could not write file for test: %v", err)
	}


	var fs billy.Filesystem

	// when reading gitignores starting at the REPO root
	d = filepath.Join(tDir, "git_repo/")
	fs = osfs.New(d)

	// ReadPatterns(fs billy.Filesystem, path []string) (ps []gitignore.Pattern, err error) {

	patterns, err := customgitignore.ReadPatterns(fs, []string{"."})
	if err != nil {
		t.Fatalf("could not read gitignore patterns for test: %v", err)
	}

	fmt.Printf("PATT: %d\n", len(patterns))

	for i, pp := range patterns {
		fmt.Printf("PATT: %d, %v\n", i, pp)
	}

	// p0 := patterns[1]
	// path := []string{tDir, "git_repo:.gitignore-file"}
	// // Match(path []string, isDir bool) MatchResult
	// fmt.Printf("IS_MATCH: %t\n", p0.Match(path, false) == gitignore.Exclude)

	fmt.Println("SUCCESS!")

	// // given, the main REPO/.gitignore file has a /dir_a/dir_b pattern
	// //
	// // expect, /dir_a/.gitignore pattern to be processed
	// if patterns_not_include_something {
	// 		t.Fatalf("could not write file for test: %v", err)
	// }
	// // expect, /dir_a/dir_b/.gitignore not to be processed
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


// func TestNew(t *testing.T) {
// 	t.Parallel()

// 	for _, format := range reporter.Format() {
// 		stdout := &bytes.Buffer{}
// 		stderr := &bytes.Buffer{}

// 		_, err := reporter.New(format, stdout, stderr, reporter.InfoLevel, 0)
// 		if err != nil {
// 			t.Errorf("Reporter for '%s' format not implemented", format)
// 		}
// 	}
// }

// func TestNew_UnsupportedFormatter(t *testing.T) {
// 	t.Parallel()

// 	stdout := &bytes.Buffer{}
// 	stderr := &bytes.Buffer{}

// 	_, err := reporter.New("unsupported", stdout, stderr, reporter.InfoLevel, 0)

// 	if err == nil {
// 		t.Errorf("Did not get expected error")
// 	}
// }
// package main

// import (
// 	"fmt"
// )
