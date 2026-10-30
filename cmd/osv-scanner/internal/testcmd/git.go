package testcmd

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
)

func SetupGitFixtures() (func(), error) {
	// ensure a git repository doesn't already exist in the testdata directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./testdata/.git")

	toRemove := []string{"./testdata/.git"}

	cleaner := func() {
		for _, p := range toRemove {
			os.RemoveAll(p)
		}
	}

	// temporarily make the testdata folder a git repository to prevent gitignore files messing with tests
	_, err := git.PlainInit("./testdata", false)
	if err != nil {
		return cleaner, err
	}

	var gitIgnoreFiles []string

	// walk the testdata to find all test .gitignore files that should be copied before tests run
	err = filepath.Walk("./testdata", func(path string, info fs.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Base(path) == "test.gitignore" {
			gitIgnoreFiles = append(gitIgnoreFiles, path)
		}

		return nil
	})

	if err != nil {
		return cleaner, err
	}

	for _, f := range gitIgnoreFiles {
		gitignoreFile, err := CopyFile(f, filepath.Join(filepath.Dir(f), ".gitignore"))

		if err != nil {
			return cleaner, err
		}

		toRemove = append(toRemove, gitignoreFile)
	}

	return cleaner, nil
}
