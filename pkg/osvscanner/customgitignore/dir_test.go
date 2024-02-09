// TODO: check if there's a way to make this: `package customgitignore` instead
package customgitignore_test

import (
	"fmt"
	"testing"
	"os"
	"path/filepath"
	"slices"
	"reflect"

	"github.com/google/osv-scanner/pkg/osvscanner/customgitignore"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

func TestBigBallOTest(t *testing.T) {
	// Vars for re-use: file, dir, text
	var f, d string
	var s string
	var err error

	// Create a test-local tempdir
	tDir := t.TempDir()

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
	s = "ROOT_GITIGNORE" + "\n" +
		  "/dir_a/dir_b"
	err = os.WriteFile(f, []byte(s), 0644)
	if err != nil {
		t.Fatalf("could not write file for test: %v", err)
	}

	f = filepath.Join(tDir, "git_repo/dir_a/.gitignore")
	s = "DIR_A_GITIGNORE"
	err = os.WriteFile(f, []byte(s), 0644)
	if err != nil {
		t.Fatalf("could not write file for test: %v", err)
	}

	f = filepath.Join(tDir, "git_repo/dir_a/dir_b/.gitignore")
	s = "DIR_B_GITIGNORE"
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


	// TESTING

	fmt.Printf("PATT-COUNT: %d\n", len(patterns))

	for i, pp := range patterns {
		fmt.Printf("PATT: %d:  %#v (%T)\n", i, pp, pp)
	}

	// PATT-COUNT: 3
	// PATT: 0:  &gitignore.pattern{domain:[]string{"."}, pattern:[]string{"ROOT_GITIGNORE"}, inclusion:false, dirOnly:false, isGlob:false} (*gitignore.pattern)
	// PATT: 1:  &gitignore.pattern{domain:[]string{"."}, pattern:[]string{"", "dir_a", "dir_b"}, inclusion:false, dirOnly:false, isGlob:true} (*gitignore.pattern)
	// PATT: 2:  &gitignore.pattern{domain:[]string{".", "dir_a"}, pattern:[]string{"DIR_A_GITIGNORE"}, inclusion:false, dirOnly:false, isGlob:false} (*gitignore.pattern)
	// SUCCESS!

	// TODO: using ToSlash and FromSlash with path.Fn calls to do all work in "/" separated paths then handle conversion when you use os.Fns

	// p1 := patterns[0]
	// // path := []string{tDir, "ROOT_GITIGNORE"}
	// // path = path.split(os.path.sep)
	// pathSlice := []string{".", "ROOT_GITIGNORE"}
	// fmt.Println("---")
	// fmt.Printf("path == %#v\n", pathSlice)
	// fmt.Printf("p1 == %#v\n", p1)
	// dir, err := os.Getwd() ; fmt.Printf("cwd == %#v\n", dir)
	// fmt.Println("---")
	// // Match(path []string, isDir bool) MatchResult
	// rslt := p1.Match(pathSlice, false)
	// fmt.
	// fmt.Printf("IS_MATCH: val==%v bool==%t\n", rslt, rslt == gitignore.Exclude)

	var hasMatch bool

	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "ROOT_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Fatalf("Expected to find a pattern matching ROOT_GITIGNORE from repository-root .gitignore")
	}

	hasMatch = slices.ContainsFunc(patterns, func(p gitignore.Pattern) bool {
		return p.Match([]string{".", "dir_a", "DIR_A_GITIGNORE"}, false) == gitignore.Exclude
	})

	if !hasMatch {
		t.Fatalf("Expected to find a pattern matching dir_a/DIR_A_GITIGNORE from ./dir_a/.gitignore")
	}

	// REMOVE:


	// I want to test for the lack of a GITIGNORE_B match,
	// to show that dir_a/dir_b/.gitignore wasn't read,
	// but the `dir_a/dir_b` pattern from .GITIGNORE_ROOT
	// prevents this.
	// Instead I'm doing dubious `reflect` hackery to get
	// accecss to the unxported `Pattern.pattern` field
	for _, pattern := range patterns {
		// dubious `reflect` hackery means: slice := pattern.pattern
		fv := reflect.ValueOf(pattern).Elem().FieldByName("pattern")
		// slice := fv.Slice(0, fv.Len())

		// fmt.Printf("%v (1/%v) \n", fv.Index(0), fv.Len())

		// tests if pattern.patter == []string{"DIR_B_GITIGNORE"}
		if fv.Len() == 1 && fv.Index(0).String() == "DIR_B_GITIGNORE" {
		// if slices.Contains(slice, "DIR_B_GITIGNORE") {
			t.Fatalf(	"Expected not to find pattern matching DIR_B_GITIGNORE from ./dir_a/dir_b/.gitignore; " +
								"dir_b should have been ignored by a rule in repository-root .gitignore")
		}
	}


	// --------------------------------


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
