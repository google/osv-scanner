// based on https://github.com/go-git/go-git/blob/v5.7.0/plumbing/format/gitignore/dir.go
// but modified so that it skips ignored directories while traversing for gitignore files

package customgitignore

import (
	"bufio"
	"os"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

const (
	commentPrefix   = "#"
	gitDir          = ".git"
	gitignoreFile   = ".gitignore"
	infoExcludeFile = gitDir + "/info/exclude"
)

// readIgnoreFile reads a specific git ignore file.
func readIgnoreFile(fs billy.Filesystem, path []string, ignoreFile string) (ps []gitignore.Pattern, err error) {
	f, err := fs.Open(fs.Join(append(path, ignoreFile)...))
	if err == nil {
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			s := scanner.Text()
			if !strings.HasPrefix(s, commentPrefix) && len(strings.TrimSpace(s)) > 0 {
				ps = append(ps, gitignore.ParsePattern(s, path))
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	return
}

// ReadPatterns reads the .git/info/exclude and then the gitignore patterns
// recursively traversing through the directory structure. The result is in
// the ascending order of priority (last higher).
func ReadPatterns(fs billy.Filesystem, path []string) (ps []gitignore.Pattern, err error) {
	ps, _ = readIgnoreFile(fs, path, infoExcludeFile)
	subps, err := ReadPatternsIgnoringDirs(fs, path, ps)
	ps = append(ps, subps...)

	return ps, err
}

// ReadPatternsIgnoringDirs keeps track of the patterns it has read so far,
// and does not parse directories these match for efficiency.
//
// Optionally a list of existing patterns to ignore can be supplied.
func ReadPatternsIgnoringDirs(fs billy.Filesystem, path []string, accumulatedPs []gitignore.Pattern) (ps []gitignore.Pattern, err error) {
	ps, err = readIgnoreFile(fs, path, gitignoreFile)
	if err != nil {
		return ps, err
	}

	var fis []os.FileInfo
	fis, err = fs.ReadDir(fs.Join(path...))
	if err != nil {
		return ps, err
	}

	accumulatedPs = append(accumulatedPs, ps...)
	matcherForThisDir := gitignore.NewMatcher(accumulatedPs)

	for _, fi := range fis {
		if fi.IsDir() && fi.Name() != gitDir {
			childPath := path
			childPath = append(childPath, fi.Name())
			if !matcherForThisDir.Match(childPath, fi.IsDir()) {
				var subps []gitignore.Pattern
				subps, err = ReadPatternsIgnoringDirs(fs, childPath, accumulatedPs)
				if err != nil {
					return ps, err
				}

				if len(subps) > 0 {
					ps = append(ps, subps...)
				}
			}
		}
	}

	return ps, err
}
