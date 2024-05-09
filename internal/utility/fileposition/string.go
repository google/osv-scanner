package fileposition

import (
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

func ExtractStringPositionInBlock(block []string, str string, blockStartLine int) *models.FilePosition {
	return ExtractDelimitedStringPositionInBlock(block, str, blockStartLine, "", "")
}

func ExtractDelimitedStringPositionInBlock(block []string, str string, blockStartLine int, prefix string, suffix string) *models.FilePosition {
	for i, line := range block {
		search := prefix + str + suffix
		if strings.Contains(line, search) {
			linePosition := blockStartLine + i
			columnStart := strings.Index(line, str) + 1
			columnEnd := columnStart + len(str)

			return &models.FilePosition{
				Line:   models.Position{Start: linePosition, End: linePosition},
				Column: models.Position{Start: columnStart, End: columnEnd},
			}
		}
	}

	return nil
}
