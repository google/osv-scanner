package semantic

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

type PyPIVersion struct {
	epoch   *big.Int
	release Components
	pre     letterAndNumber
	post    letterAndNumber
	dev     letterAndNumber
	local   []string
	legacy  []string
}

type letterAndNumber struct {
	letter string
	number *big.Int
}

func parseLetterVersion(letter, number string) letterAndNumber {
	if letter != "" {
		// we consider there to be an implicit 0 in a pre-release
		// if there is not a numeral associated with it
		if number == "" {
			number = "0"
		}

		// we normalize any letters to their lowercase form
		letter = strings.ToLower(letter)

		// we consider some words to be alternative spellings of other words and in
		// those cases we want to normalize the spellings to our preferred spelling
		switch letter {
		case "alpha":
			letter = "a"
		case "beta":
			letter = "b"
		case "c":
			fallthrough
		case "pre":
			fallthrough
		case "preview":
			letter = "rc"
		case "rev":
			fallthrough
		case "r":
			letter = "post"
		}

		return letterAndNumber{letter, convertToBigIntOrPanic(number)}
	}

	if number != "" {
		// we assume if we're given a number but not a letter then this is using
		// the implicit post release syntax (e.g. 1.0-1)
		letter = "post"

		return letterAndNumber{letter, convertToBigIntOrPanic(number)}
	}

	return letterAndNumber{}
}

func parseLocalVersion(local string) (parts []string) {
	for _, part := range cachedregexp.MustCompile(`[._-]`).Split(local, -1) {
		parts = append(parts, strings.ToLower(part))
	}

	return parts
}

func normalizePyPILegacyPart(part string) string {
	switch part {
	case "pre":
		part = "c"
	case "preview":
		part = "c"
	case "-":
		part = "final-"
	case "rc":
		part = "c"
	case "dev":
		part = "@"
	}

	if cachedregexp.MustCompile(`\d`).MatchString(part[:1]) {
		// pad for numeric comparison
		return fmt.Sprintf("%08s", part)
	}

	return "*" + part
}

func parsePyPIVersionParts(str string) (parts []string) {
	re := cachedregexp.MustCompile(`(\d+|[a-z]+|\.|-)`)

	splits := re.FindAllString(str, -1)
	splits = append(splits, "final")

	for _, part := range splits {
		if part == "" || part == "." {
			continue
		}

		part = normalizePyPILegacyPart(part)

		if strings.HasPrefix(part, "*") {
			if strings.Compare(part, "*final") < 0 {
				for len(parts) > 0 && parts[len(parts)-1] == "*final-" {
					parts = parts[:len(parts)-1]
				}
			}

			for len(parts) > 0 && parts[len(parts)-1] == "00000000" {
				parts = parts[:len(parts)-1]
			}
		}

		parts = append(parts, part)
	}

	return parts
}

func parsePyPILegacyVersion(str string) PyPIVersion {
	parts := parsePyPIVersionParts(str)

	return PyPIVersion{epoch: big.NewInt(-1), legacy: parts}
}

func parsePyPIVersion(str string) PyPIVersion {
	str = strings.ToLower(str)

	// from https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
	re := cachedregexp.MustCompile(`^\s*v?(?:(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*$`)
	match := re.FindStringSubmatch(str)

	if len(match) == 0 {
		return parsePyPILegacyVersion(str)
	}

	var version PyPIVersion

	version.epoch = big.NewInt(0)

	if epoch := match[re.SubexpIndex("epoch")]; epoch != "" {
		version.epoch = convertToBigIntOrPanic(epoch)
	}

	for _, r := range strings.Split(match[re.SubexpIndex("release")], ".") {
		version.release = append(version.release, convertToBigIntOrPanic(r))
	}

	version.pre = parseLetterVersion(match[re.SubexpIndex("pre_l")], match[re.SubexpIndex("pre_n")])

	post := match[re.SubexpIndex("post_n1")]

	if post == "" {
		post = match[re.SubexpIndex("post_n2")]
	}

	version.post = parseLetterVersion(match[re.SubexpIndex("post_l")], post)
	version.dev = parseLetterVersion(match[re.SubexpIndex("dev_l")], match[re.SubexpIndex("dev_n")])
	version.local = parseLocalVersion(match[re.SubexpIndex("local")])

	return version
}

// Compares the epoch segments of each version
func (pv PyPIVersion) compareEpoch(pw PyPIVersion) int {
	return pv.epoch.Cmp(pw.epoch)
}

// Compares the release segments of each version, which considers the numeric value
// of each component in turn; when comparing release segments with different numbers
// of components, the shorter segment is padded out with additional zeros as necessary.
func (pv PyPIVersion) compareRelease(pw PyPIVersion) int {
	return pv.release.Cmp(pw.release)
}

func (pv PyPIVersion) preIndex() int {
	for i, pre := range []string{"a", "b", "rc"} {
		if pre == pv.pre.letter {
			return i
		}
	}

	panic("unknown prefix " + pv.pre.letter)
}

// Checks if this PyPIVersion should apply a sort trick when comparing pre,
// which ensures that i.e. 1.0.dev0 is before 1.0a0.
func (pv PyPIVersion) shouldApplyPreTrick() bool {
	return pv.pre.number == nil && pv.post.number == nil && pv.dev.number != nil
}

// Compares the pre-release segment of each version, which consist of an alphabetical
// identifier for the pre-release phase, along with a non-negative integer value.
//
// Pre-releases for a given release are ordered first by phase (alpha, beta, release
// candidate) and then by the numerical component within that phase.
//
// Versions without a pre-release are sorted after those with one.
func (pv PyPIVersion) comparePre(pw PyPIVersion) int {
	switch {
	case pv.shouldApplyPreTrick() && pw.shouldApplyPreTrick():
		return +0
	case pv.shouldApplyPreTrick():
		return -1
	case pw.shouldApplyPreTrick():
		return +1
	case pv.pre.number == nil && pw.pre.number == nil:
		return +0
	case pv.pre.number == nil:
		return +1
	case pw.pre.number == nil:
		return -1
	default:
		ai := pv.preIndex()
		bi := pw.preIndex()

		if ai == bi {
			return pv.pre.number.Cmp(pw.pre.number)
		}

		if ai > bi {
			return +1
		}
		if ai < bi {
			return -1
		}

		return 0
	}
}

// Compares the post-release segment of each version.
//
// Post-releases are ordered by their numerical component, immediately following
// the corresponding release, and ahead of any subsequent release.
//
// Versions without a post segment are sorted before those with one.
func (pv PyPIVersion) comparePost(pw PyPIVersion) int {
	switch {
	case pv.post.number == nil && pw.post.number == nil:
		return +0
	case pv.post.number == nil:
		return -1
	case pw.post.number == nil:
		return +1
	default:
		return pv.post.number.Cmp(pw.post.number)
	}
}

// Compares the dev-release segment of each version, which consists of the string
// ".dev" followed by a non-negative integer value.
//
// Developmental releases are ordered by their numerical component, immediately
// before the corresponding release (and before any pre-releases with the same release segment),
// and following any previous release (including any post-releases).
//
// Versions without a development segment are sorted after those with one.
func (pv PyPIVersion) compareDev(pw PyPIVersion) int {
	switch {
	case pv.dev.number == nil && pw.dev.number == nil:
		return +0
	case pv.dev.number == nil:
		return +1
	case pw.dev.number == nil:
		return -1
	default:
		return pv.dev.number.Cmp(pw.dev.number)
	}
}

// Compares the local segment of each version
func (pv PyPIVersion) compareLocal(pw PyPIVersion) int {
	min := minInt(len(pv.local), len(pw.local))

	var compare int

	for i := 0; i < min; i++ {
		ai, aIsNumber := convertToBigInt(pv.local[i])
		bi, bIsNumber := convertToBigInt(pw.local[i])

		switch {
		// If a segment consists entirely of ASCII digits then that section should be considered an integer for comparison purposes
		case aIsNumber && bIsNumber:
			compare = ai.Cmp(bi)
		// If a segment contains any ASCII letters then that segment is compared lexicographically with case insensitivity.
		case !aIsNumber && !bIsNumber:
			compare = strings.Compare(pv.local[i], pw.local[i])
		// When comparing a numeric and lexicographic segment, the numeric section always compares as greater than the lexicographic segment.
		case aIsNumber:
			compare = +1
		default:
			compare = -1
		}

		if compare != 0 {
			if compare > 0 {
				return 1
			}

			return -1
		}
	}

	// Additionally a local version with a great number of segments will always compare as greater than a local version with fewer segments,
	// as long as the shorter local version’s segments match the beginning of the longer local version’s segments exactly.
	if len(pv.local) > len(pw.local) {
		return +1
	}
	if len(pv.local) < len(pw.local) {
		return -1
	}

	return 0
}

// Compares the legacy segment of each version.
//
// These are versions that predate and are incompatible with PEP 440 - comparing
// is "best effort" since there isn't a strong specification defined, and are
// always considered lower than PEP 440 versions to match current day tooling.
//
// http://peak.telecommunity.com/DevCenter/setuptools#specifying-your-project-s-version
// looks like a good reference, but unsure where it sits in the actual tooling history
func (pv PyPIVersion) compareLegacy(pw PyPIVersion) int {
	if len(pv.legacy) == 0 && len(pw.legacy) == 0 {
		return +0
	}
	if len(pv.legacy) == 0 && len(pw.legacy) != 0 {
		return +1
	}
	if len(pv.legacy) != 0 && len(pw.legacy) == 0 {
		return -1
	}

	return strings.Compare(
		strings.Join(pv.legacy, ""),
		strings.Join(pw.legacy, ""),
	)
}

func pypiCompareVersion(v, w PyPIVersion) int {
	if legacyDiff := v.compareLegacy(w); legacyDiff != 0 {
		return legacyDiff
	}
	if epochDiff := v.compareEpoch(w); epochDiff != 0 {
		return epochDiff
	}
	if releaseDiff := v.compareRelease(w); releaseDiff != 0 {
		return releaseDiff
	}
	if preDiff := v.comparePre(w); preDiff != 0 {
		return preDiff
	}
	if postDiff := v.comparePost(w); postDiff != 0 {
		return postDiff
	}
	if devDiff := v.compareDev(w); devDiff != 0 {
		return devDiff
	}
	if localDiff := v.compareLocal(w); localDiff != 0 {
		return localDiff
	}

	return 0
}

func (pv PyPIVersion) Compare(pw PyPIVersion) int {
	return pypiCompareVersion(pv, pw)
}

func (pv PyPIVersion) CompareStr(str string) int {
	return pv.Compare(parsePyPIVersion(str))
}
