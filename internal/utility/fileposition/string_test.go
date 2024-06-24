package fileposition

import (
	"testing"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestBytesToLines(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		data  []byte
		lines []string
	}{
		{
			data:  []byte(""),
			lines: []string{""},
		},
		{
			data:  []byte("1\n2\n3"),
			lines: []string{"1", "2", "3"},
		},
	}

	for _, tt := range testCases {
		assert.Equal(t, tt.lines, BytesToLines(tt.data))
	}
}

func TestExtractDelimitedStringPositionInBlock(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		block          []string
		str            string
		blockStartLine int
		prefix         string
		suffix         string
		position       *models.FilePosition
	}{
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "jk",
			blockStartLine: 1,
			position: &models.FilePosition{
				Line:   models.Position{Start: 2, End: 2},
				Column: models.Position{Start: 4, End: 6},
			},
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "af",
			blockStartLine: 1,
			position:       nil,
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "jk",
			blockStartLine: 1,
			prefix:         "ghi",
			suffix:         "l",
			position: &models.FilePosition{
				Line:   models.Position{Start: 2, End: 2},
				Column: models.Position{Start: 4, End: 6},
			},
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "jk",
			blockStartLine: 1,
			prefix:         "ab",
			suffix:         "l",
			position:       nil,
		},
	}

	for _, tt := range testCases {
		assert.Equal(t, tt.position, ExtractDelimitedStringPositionInBlock(tt.block, tt.str, tt.blockStartLine, tt.prefix, tt.suffix))
	}
}

func TestExtractDelimitedRegexpPositionInBlock(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		block          []string
		str            string
		blockStartLine int
		prefix         string
		suffix         string
		position       *models.FilePosition
	}{
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "h.*l",
			blockStartLine: 1,
			position: &models.FilePosition{
				Line:   models.Position{Start: 2, End: 2},
				Column: models.Position{Start: 2, End: 7},
			},
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "(h.*)l",
			blockStartLine: 1,
			position: &models.FilePosition{
				Line:   models.Position{Start: 2, End: 2},
				Column: models.Position{Start: 2, End: 7},
			},
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "a+kl",
			blockStartLine: 1,
			position:       nil,
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "i+j",
			blockStartLine: 1,
			prefix:         "gh",
			suffix:         "kl",
			position: &models.FilePosition{
				Line:   models.Position{Start: 2, End: 2},
				Column: models.Position{Start: 3, End: 5},
			},
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "i+j",
			blockStartLine: 1,
			prefix:         "([agm]*)",
			suffix:         "(@npm)?",
			position: &models.FilePosition{
				Line:   models.Position{Start: 2, End: 2},
				Column: models.Position{Start: 3, End: 5},
			},
		},
		{
			block:          []string{"abcdef", "ghijkl", "mnopqr"},
			str:            "i?k",
			blockStartLine: 1,
			prefix:         "ab",
			suffix:         "l",
			position:       nil,
		},
	}

	for _, tt := range testCases {
		assert.Equal(t, tt.position, ExtractDelimitedRegexpPositionInBlock(tt.block, tt.str, tt.blockStartLine, tt.prefix, tt.suffix))
	}
}
