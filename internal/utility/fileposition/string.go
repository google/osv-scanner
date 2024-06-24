package fileposition

import (
	"slices"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"

	"github.com/google/osv-scanner/pkg/models"
)

func BytesToLines(data []byte) []string {
	re := cachedregexp.MustCompile(`\r\n|\r|\n`)
	str := string(data)
	lines := re.Split(str, -1)

	return lines
}

func extractPositionFromLine(linePosition int, line string, str string) *models.FilePosition {
	columnStart := strings.Index(line, str) + 1
	columnEnd := columnStart + len(str)

	return &models.FilePosition{
		Line:   models.Position{Start: linePosition, End: linePosition},
		Column: models.Position{Start: columnStart, End: columnEnd},
	}
}

func ExtractStringPositionInBlock(block []string, str string, blockStartLine int) *models.FilePosition {
	if len(str) == 0 {
		return nil
	}

	return ExtractDelimitedStringPositionInBlock(block, str, blockStartLine, "", "")
}

func ExtractDelimitedStringPositionInBlock(block []string, str string, blockStartLine int, prefix string, suffix string) *models.FilePosition {
	for i, line := range block {
		search := prefix + str + suffix
		if strings.Contains(line, search) {
			return extractPositionFromLine(blockStartLine+i, line, str)
		}
	}

	return nil
}

func ExtractRegexpPositionInBlock(block []string, str string, blockStartLine int) *models.FilePosition {
	return ExtractDelimitedRegexpPositionInBlock(block, str, blockStartLine, "", "")
}

func QuoteMetaDelimiters(prefix string, suffix string) (string, string) {
	return cachedregexp.QuoteMeta(prefix), cachedregexp.QuoteMeta(suffix)
}

func ExtractDelimitedRegexpPositionInBlock(block []string, str string, blockStartLine int, prefix string, suffix string) *models.FilePosition {
	// We name the group we are looking for in order to identify it after in the matches
	// This is required due to the fact that prefix and suffix could also be regex and contain other groups
	term := "(?P<term>" + str + ")"
	regex := cachedregexp.MustCompile(prefix + term + suffix)
	for i, line := range block {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Replace regexp with captured value
			// We use the named group to identify the captured value
			str = matches[slices.Index(regex.SubexpNames(), "term")]

			return extractPositionFromLine(blockStartLine+i, line, str)
		}
	}

	return nil
}
