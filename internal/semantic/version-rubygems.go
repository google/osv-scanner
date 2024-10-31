package semantic

import (
	"strings"
)

func canonicalizeRubyGemVersion(str string) string {
	res := ""

	checkPrevious := false
	previousWasDigit := true

	for _, c := range str {
		if c == 46 {
			checkPrevious = false
			res += "."

			continue
		}

		isDigit := c >= 48 && c <= 57

		if checkPrevious && previousWasDigit != isDigit {
			res += "."
		}

		res += string(c)

		previousWasDigit = isDigit
		checkPrevious = true
	}

	return res
}

func groupSegments(segs []string) (numbers []string, build []string) {
	for _, seg := range segs {
		_, isNumber := convertToBigInt(seg)

		if len(build) > 0 || !isNumber {
			build = append(build, seg)

			continue
		}

		numbers = append(numbers, seg)
	}

	return numbers, build
}

func removeZeros(segs []string) []string {
	i := len(segs) - 1

	for i >= 0 {
		if segs[i] != "0" {
			i++

			break
		}

		i--
	}

	return segs[:max(i, 0)]
}

func canonicalSegments(segs []string) (canSegs []string) {
	numbers, build := groupSegments(segs)

	return append(removeZeros(numbers), removeZeros(build)...)
}

func compareRubyGemsComponents(a, b []string) int {
	numberOfComponents := max(len(a), len(b))

	for i := range numberOfComponents {
		as := fetch(a, i, "0")
		bs := fetch(b, i, "0")

		ai, aIsNumber := convertToBigInt(as)
		bi, bIsNumber := convertToBigInt(bs)

		switch {
		case aIsNumber && bIsNumber:
			if diff := ai.Cmp(bi); diff != 0 {
				return diff
			}
		case !aIsNumber && !bIsNumber:
			if diff := strings.Compare(as, bs); diff != 0 {
				return diff
			}
		case aIsNumber:
			return +1
		default:
			return -1
		}
	}

	return 0
}

type RubyGemsVersion struct {
	Original string
	Segments []string
}

func parseRubyGemsVersion(str string) RubyGemsVersion {
	return RubyGemsVersion{
		str,
		canonicalSegments(strings.Split(canonicalizeRubyGemVersion(str), ".")),
	}
}

func (v RubyGemsVersion) Compare(w RubyGemsVersion) int {
	return compareRubyGemsComponents(v.Segments, w.Segments)
}

func (v RubyGemsVersion) CompareStr(str string) int {
	return v.Compare(parseRubyGemsVersion(str))
}
