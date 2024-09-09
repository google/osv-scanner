package lockfile

import (
	"bufio"
	"errors"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/maps"
	"io"
	"path/filepath"
	"regexp"
)

// Adds support for parsing the `install_requires` key if it uses plain string values
// Any dependencies described in other requires keys are not scanned
// Fails fast on unsupported inputs

type SetupPyExtractor struct{}

func (e SetupPyExtractor) ShouldExtract(path string) bool {
	// TODO: should we check we are in the root of a module?
	return filepath.Base(path) == "setup.py"
}

var requirementRegexp = regexp.MustCompile(`\s*(?P<pkgname>[a-zA-Z0-9._-]+)\s*(?P<pkgversionspec>(~=|==|!=|<=|>=|<|>|===)[a-zA-Z0-9._!-]+)?\s*`)

const InstallRequiresKeyword = "install_requires"

var SkipRunes = map[rune]struct{}{
	' ':  {},
	'\t': {},
	'\r': {},
	'\f': {},
	',':  {},
}

func (e SetupPyExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var lineNumber, columnStart int = 1, 1

	packages := map[string]PackageDetails{}

	inInstallRequires := false
	inEqual := false
	inArray := false
	r := bufio.NewReader(f)

out:
	for {
		var rn rune
		var runeSize int
		var err error
		if rn, runeSize, err = r.ReadRune(); err != nil {
			return nil, err
		}
		columnStart += runeSize

		// Skip comments, even before install_requires, as they are not relevant
		// and might incorrectly trigger install_requires start
		skippedComment, err := skipComment(rn, r)
		if err != nil {
			return nil, err
		} else if skippedComment {
			lineNumber++
			columnStart = 1
			continue out
		}

		if rn == '\n' {
			lineNumber++
			columnStart = 1
			continue
		}

		if !inInstallRequires {
			isInstallRequires, err := checkInstallRequires(rn, r)
			if err != nil {
				return nil, err
			} else if isInstallRequires {
				inInstallRequires = true
			}

			continue
		}

		if _, ok := SkipRunes[rn]; ok {
			// skip
		} else if rn == '=' {
			if inEqual {
				return nil, errors.New("unexpected equal inside already started equal")
			}
			inEqual = true
		} else if rn == '[' {
			if !inEqual {
				return nil, errors.New("unexpected array start without =")
			}
			if inArray {
				return nil, errors.New("unexpected array start inside already started array")
			}
			inArray = true
		} else if rn == ']' {
			if !inEqual || !inArray {
				return nil, errors.New("unexpected array end without start and/or equal")
			}
			return maps.Values(packages), nil
		} else if rn == '\'' || rn == '"' {
			if !inArray {
				return nil, errors.New("unexpected string outside of install_requires with equal array")
			}

			requirement, err := readRemainingStringUntil(rn, r, &rn)
			if err != nil {
				return nil, err
			}

			matches := requirementRegexp.FindStringSubmatch(requirement)

			packageName := matches[requirementRegexp.SubexpIndex("pkgname")]
			versionIdx := requirementRegexp.SubexpIndex("pkgversionspec")
			var packageVersion string
			if versionIdx != -1 {
				packageVersion = matches[versionIdx]
			}

			nameColumnEnd := columnStart + len(packageName)
			nameLocation := models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: columnStart, End: nameColumnEnd},
				Filename: f.Path(),
			}

			versionColumnEnd := nameColumnEnd + len(packageVersion)
			versionLocation := models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: nameColumnEnd, End: versionColumnEnd},
				Filename: f.Path(),
			}

			blockLocation := models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: columnStart, End: versionColumnEnd},
				Filename: f.Path(),
			}

			packages[packageName] = PackageDetails{
				Name:            packageName,
				Version:         packageVersion,
				PackageManager:  models.Requirements,
				Ecosystem:       PipEcosystem,
				CompareAs:       PipEcosystem,
				BlockLocation:   blockLocation,
				NameLocation:    &nameLocation,
				VersionLocation: &versionLocation,
			}
		} else {
			text, err := readRemainingStringUntil(rn, r, nil)
			if err != nil {
				return nil, err
			}

			return nil, errors.New("unexpected text=" + text)
		}
	}
}

func readRemainingStringUntil(current rune, r *bufio.Reader, end *rune) (string, error) {
	var text string
	text += string(current)
	for {
		rn, _, err := r.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return "", err
			}
		}
		if end != nil && rn == *end {
			break
		}
		text += string(rn)
	}

	return text, nil
}

func skipComment(current rune, r *bufio.Reader) (bool, error) {
	// Skip comments, even before install_requires, as they are not relevant
	// and might incorrectly trigger install_requires start
	if current == '#' {
		for {
			rn, _, err := r.ReadRune()
			if err != nil {
				if err == io.EOF {
					return false, errors.New("unexpected end of file")
				} else {
					return false, err
				}
			}
			if rn == '\n' {
				return true, nil
			}
		}
	}

	return false, nil
}

func checkInstallRequires(current rune, r *bufio.Reader) (bool, error) {
	for pos, keywordRune := range InstallRequiresKeyword {
		if pos == 0 {
			if current != keywordRune {
				return false, nil
			}

			continue
		}

		bufferRune, _, err := r.ReadRune()
		if err != nil {
			if err == io.EOF {
				return false, nil
			} else {
				return false, err
			}
		}
		if bufferRune != keywordRune {
			return false, nil
		}
	}

	return true, nil
}

var _ Extractor = SetupPyExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("setup.py", SetupPyExtractor{})
}

func ParseSetupPy(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, SetupPyExtractor{})
}
