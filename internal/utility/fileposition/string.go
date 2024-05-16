package fileposition

import (
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"

	"github.com/google/osv-scanner/pkg/models"
)

func BytesToLines(data []byte) []string {
	str := string(data)
	return strings.Split(str, "\n")
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

func ExtractDelimitedRegexpPositionInBlock(block []string, str string, blockStartLine int, prefix string, suffix string) *models.FilePosition {
	// We expect 'str' to be a literal value or in case it is a regexp to be only one capturing group
	regex := cachedregexp.MustCompile(cachedregexp.QuoteMeta(prefix) + str + cachedregexp.QuoteMeta(suffix))
	for i, line := range block {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// A group was captured -> Replace group regexp with captured value
			if len(matches) == 2 {
				str = matches[1]
			}

			return extractPositionFromLine(blockStartLine+i, line, str)
		}
	}

	return nil
}
