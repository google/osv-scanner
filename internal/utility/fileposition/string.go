package fileposition

import (
	"fmt"
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
	group := fmt.Sprintf("(%s)", str)
	regex := cachedregexp.MustCompile(cachedregexp.QuoteMeta(prefix) + group + cachedregexp.QuoteMeta(suffix))
	for i, line := range block {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Replace regexp with captured value
			str = matches[1]

			return extractPositionFromLine(blockStartLine+i, line, str)
		}
	}

	return nil
}
