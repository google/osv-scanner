package semantic

import (
	"math/big"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

// AlpineVersion represents a version of an Alpine package.
//
// Currently, the APK version specification is as follows:
// *number{.number}...{letter}{\_suffix{number}}...{~hash}{-r#}*
//
// Each *number* component is a sequence of digits (0-9).
//
// The *letter* portion can follow only after end of all the numeric
// version components. The *letter* is a single lower case letter (a-z).
// This can follow one or more *\_suffix{number}* components. The list
// of valid suffixes (and their sorting order) is:
// *alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*
//
// This can be follows with an optional *{~hash}* to indicate a commit
// hash from where it was built. This can be any length string of
// lower case hexadecimal digits (0-9a-f).
//
// Finally, an optional package build component *-r{number}* can follow.
//
// Also see https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd#package-info-metadata
type AlpineVersion struct {
	// slice of number components which can be compared in a semver-like manner
	components Components
	// optional single lower-case letter
	letter string
	// slice of one or more suffixes, prefixed with "_" and optionally followed by a number.
	//
	// supported suffixes and their sort order are:
	//	*alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*
	suffixes []string
	// optional commit hash made up of any number of lower case hexadecimal digits (0-9a-f)
	hash string
	// prefixed with "-r{number}"
	buildComponent *big.Int
}

func (v AlpineVersion) Compare(w AlpineVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}

	return 0
}

func (v AlpineVersion) CompareStr(str string) int {
	return v.Compare(parseAlpineVersion(str))
}

// parseAlpineNumberComponents parses the given string into AlpineVersion.components
// and then returns the remainder of the string for continued parsing.
//
// Each number component is a sequence of digits (0-9), separated with a ".",
// and with no limit on the value or amount of number components.
//
// This parser must be applied *before* any other parser.
func parseAlpineNumberComponents(v *AlpineVersion, str string) string {
	// todo: trailing "v" (we should probably return)
	parsed := parseSemverLike(str)
	v.components = parsed.Components

	return parsed.Build
}

// parseAlpineLetter parses the given string into an AlpineVersion.letter
// and then returns the remainder of the string for continued parsing.
//
// The letter is optional, following after the numeric version components, and
// must be a single lower case letter (a-z).
//
// This parser must be applied *after* parseAlpineNumberComponents.
func parseAlpineLetter(v *AlpineVersion, str string) string {
	if cachedregexp.MustCompile(`[a-z]`).MatchString(str[:0]) {
		v.letter = str[:0]
	}

	return strings.TrimPrefix(str, v.letter)
}

// parseAlpineSuffixes parses the given string into AlpineVersion.suffixes and
// then returns the remainder of the string for continued parsing.
//
// Suffixes begin with an "_" and may optionally end with a number.
//
// This parser must be applied *after* parseAlpineLetter.
func parseAlpineSuffixes(v *AlpineVersion, str string) string {
	re := cachedregexp.MustCompile(`_(alpha|beta|pre|rc|cvs|svn|git|hg|p)\d+`)

	for _, suffix := range re.FindAllString(str, -1) {
		v.suffixes = append(v.suffixes, suffix)
		str = strings.TrimSuffix(str, suffix)
	}

	return str
}

// parseAlpineHash parses the given string into AlpineVersion.hash and then returns
// the remainder of the string for continued parsing.
//
// The hash is an optional value representing a commit hash, which can be any length
// string of lower case hexadecimal digits (0-9a-f).
//
// This parser must be applied *after* parseAlpineSuffixes.
func parseAlpineHash(v *AlpineVersion, str string) string {
	re := cachedregexp.MustCompile(`([0-9a-f]+)`)

	v.hash = re.FindString(str)

	return strings.TrimPrefix(str, v.hash)
}

// parseAlpineBuildComponent parses the given string into AlpineVersion.buildComponent
// and then returns the remainder of the string for continued parsing.
//
// The build component is an optional value at the end of the version string which
// begins with "-r" followed by a number.
//
// This parser must be applied *after* parseAlpineBuildComponent
func parseAlpineBuildComponent(v *AlpineVersion, str string) string {
	re := cachedregexp.MustCompile(`-r(\d+)`)

	matches := re.FindStringSubmatch(str)

	// no build component, so nothing to do
	if matches == nil {
		return str
	}

	v.buildComponent = convertToBigIntOrPanic(matches[1])

	return strings.TrimPrefix(str, matches[0])
}

func parseAlpineVersion(str string) AlpineVersion {
	v := AlpineVersion{}

	// todo: look at making these methods on AlpineVersion (though might need a pointer receiver)
	str = parseAlpineNumberComponents(&v, str)
	str = parseAlpineLetter(&v, str)
	str = parseAlpineSuffixes(&v, str)
	str = parseAlpineHash(&v, str)
	str = parseAlpineBuildComponent(&v, str)

	return v
}
