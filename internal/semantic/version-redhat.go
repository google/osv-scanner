package semantic

import (
	"strings"
	"unicode"
)

type RedHatVersion struct {
	epoch   string
	version string
	release string
	arch    string
}

func (v RedHatVersion) CompareStr(str string) int {
	w := parseRedHatVersion(str)
	vi := -1
	wi := -1

	for {
		vi++
		wi++

		// todo: review this position
		if vi == len(v.version) || wi == len(w.version) {
			break
		}

		a := v.version[vi]
		b := w.version[wi]

		// 1. Trim anything that’s not [A-Za-z0-9] or tilde (~) from the front of both strings.
		// ...

		// 2. If both strings start with a tilde, discard it and move on to the next character.
		if a == '~' && b == '~' {
			continue
		}

		// 3. If string `a` starts with a tilde and string `b` does not, return -1 (string `a` is older); and the inverse if string `b` starts with a tilde and string `a` does not.
		if a == '~' {
			return -1
		}
		if b == '~' {
			return +1
		}

		// 4. End the loop if either string has reached zero length.
		// ... (see above) ...

		// 5. If the first character of `a` is a digit, pop the leading chunk of continuous digits from each string (which may be "" for `b` if only one `a` starts with digits). If `a` begins with a letter, do the same for leading letters.
		var iser func(r rune) bool
		if unicode.IsDigit(rune(a)) {
			iser = unicode.IsDigit
		} else {
			iser = unicode.IsLetter
		}

		// isDigit := a >= 48 && a <= 57
		ac := ""
		bc := ""

		for _, c := range v.version[:vi] {
			if !iser(c) {
				break
			}

			ac += string(c)
			vi++
		}

		for _, c := range w.version[:wi] {
			if !iser(c) {
				break
			}

			bc += string(c)
			wi++
		}

		// 6. If the segment from `b` had 0 length, return 1 if the segment from `a` was numeric, or -1 if it was alphabetic. The logical result of this is that if `a` begins with numbers and `b` does not, `a` is newer (return 1). If `a` begins with letters and `b` does not, then `a` is older (return -1). If the leading character(s) from `a` and `b` were both numbers or both letters, continue on.
		if bc == "" {
			if unicode.IsDigit(rune(a)) {
				return +1
			}

			return -1
		}

		// 7. If the leading segments were both numeric, discard any leading zeros and whichever one is longer wins. If `a` is longer than `b` (without leading zeroes), return 1, and vice versa. If they’re of the same length, continue on.
		ac = strings.TrimLeft(ac, "0")
		bc = strings.TrimLeft(bc, "0")

		// todo: double check if this length check also applies to alphabetic segments
		if len(ac) > len(bc) {
			return +1
		}
		if len(bc) > len(ac) {
			return -1
		}

		// 8. Compare the leading segments with strcmp() (or <=> in Ruby). If that returns a non-zero value, then return that value. Else continue to the next iteration of the loop.
		if diff := strings.Compare(ac, bc); diff != 0 {
			return diff
		}
	}

	panic("implement me")
}

// ParseRedHatVersion parses a Red Hat version into a RedHatVersion struct.
//
// A Red Hat version contains the following components:
// - name (of the package), represented as "n"
// - epoch, represented as "e"
// - version, represented as "v"
// - release, represented as "r"
// - architecture, represented as "a"
//
// When all components are present, the version is represented as "n-e:v-r.a",
// though only the version is actually required.
func parseRedHatVersion(str string) RedHatVersion {
	bf, af, hasColon := strings.Cut(str, ":")

	if !hasColon {
		af, bf = bf, af
	}

	// (note, we don't actually use the name)
	name, epoch, hasName := strings.Cut(bf, "-")

	if !hasName {
		epoch, name = name, epoch
	}

	middle, arch, _ := strings.Cut(af, ".")
	version, release, _ := strings.Cut(middle, "-")

	return RedHatVersion{
		epoch:   epoch,
		version: version,
		release: release,
		arch:    arch,
	}
}

// - RPM package names are made up of five parts; the package name, epoch, version, release, and architecture (NEVRA)
// - The epoch is not always included; it is assumed to be zero (0) on any packages that lack it explicitly
// - The format for the whole string is n-e:v-r.a
//
// - parsing:
//   - If there is a : in the string, everything before it is the epoch. If not, the epoch is zero.
//   - If there is a - in the remaining string, everything before the first - is the version, and everything after it is the release. If there isn’t one, the release is considered null/nill/None/whatever.
