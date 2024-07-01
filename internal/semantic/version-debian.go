package semantic

import (
	"math/big"
	"strings"
)

func splitAround(s string, sep string, reverse bool) (string, string) {
	var i int

	if reverse {
		i = strings.LastIndex(s, sep)
	} else {
		i = strings.Index(s, sep)
	}

	if i == -1 {
		return s, ""
	}

	return s[:i], s[i+1:]
}

func splitDebianDigitPrefix(str string) (*big.Int, string) {
	// find the index of the first non-digit in the string, which is the end of the prefix
	i := strings.IndexFunc(str, func(c rune) bool {
		return c < 48 || c > 57
	})

	if i == 0 || str == "" {
		return big.NewInt(0), str
	}

	if i == -1 {
		i = len(str)
	}

	return convertToBigIntOrPanic(str[:i]), str[i:]
}

func splitDebianNonDigitPrefix(str string) (string, string) {
	// find the index of the first digit in the string, which is the end of the prefix
	i := strings.IndexAny(str, "0123456789")

	if i == 0 || str == "" {
		return "", str
	}

	if i == -1 {
		i = len(str)
	}

	return str[:i], str[i:]
}

func weighDebianChar(char string) int {
	// tilde and empty take precedent
	if char == "~" {
		return 1
	}
	if char == "" {
		return 2
	}

	c := int(char[0])

	// all the letters sort earlier than all the non-letters
	if c < 65 || (c > 90 && c < 97) || c > 122 {
		c += 122
	}

	return c
}

func compareDebianVersions(a, b string) int {
	var ap, bp string
	var adp, bdp *big.Int

	// based off: https://man7.org/linux/man-pages/man7/deb-version.7.html
	for {
		if a == "" && b == "" {
			break
		}

		ap, a = splitDebianNonDigitPrefix(a)
		bp, b = splitDebianNonDigitPrefix(b)

		// First the initial part of each string consisting entirely of
		// non-digit characters is determined...
		if ap != bp {
			apSplit := strings.Split(ap, "")
			bpSplit := strings.Split(bp, "")

			for i := 0; i < max(len(ap), len(bp)); i++ {
				aw := weighDebianChar(fetch(apSplit, i, ""))
				bw := weighDebianChar(fetch(bpSplit, i, ""))

				if aw < bw {
					return -1
				}
				if aw > bw {
					return +1
				}
			}
		}

		// Then the initial part of the remainder of each string which
		// consists entirely of digit characters is determined....
		adp, a = splitDebianDigitPrefix(a)
		bdp, b = splitDebianDigitPrefix(b)

		if diff := adp.Cmp(bdp); diff != 0 {
			return diff
		}
	}

	return 0
}

type DebianVersion struct {
	epoch    *big.Int
	upstream string
	revision string
}

func (v DebianVersion) Compare(w DebianVersion) int {
	if diff := v.epoch.Cmp(w.epoch); diff != 0 {
		return diff
	}
	if diff := compareDebianVersions(v.upstream, w.upstream); diff != 0 {
		return diff
	}
	if diff := compareDebianVersions(v.revision, w.revision); diff != 0 {
		return diff
	}

	return 0
}

func (v DebianVersion) CompareStr(str string) int {
	return v.Compare(parseDebianVersion(str))
}

func parseDebianVersion(str string) DebianVersion {
	var upstream, revision string

	str = strings.TrimSpace(str)
	epoch := big.NewInt(0)

	if strings.Contains(str, ":") {
		var e string
		e, str = splitAround(str, ":", false)
		epoch = convertToBigIntOrPanic(e)
	}

	if strings.Contains(str, "-") {
		upstream, revision = splitAround(str, "-", true)
	} else {
		upstream = str
		revision = "0"
	}

	return DebianVersion{epoch, upstream, revision}
}
