package fileposition

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFirstNonEmptyCharacterIndexInLine(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		line  string
		index int
	}{
		{
			line:  "no empty characters",
			index: 1,
		},
		{
			line:  " one empty character",
			index: 2,
		},
		{
			line:  "         multiple empty character",
			index: 10,
		},
		{
			line:  "			with tabs",
			index: 4,
		},
		{
			line:  "",
			index: -1,
		},
	}

	for _, tt := range testCases {
		assert.Equal(t, tt.index, GetFirstNonEmptyCharacterIndexInLine(tt.line))
	}
}

func TestGetLastNonEmptyCharacterIndexInLine(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		line  string
		index int
	}{
		{
			line:  "a",
			index: 2,
		},
		{
			line:  "abc",
			index: 4,
		},
		{
			line:  "abc  ",
			index: 4,
		},
		{
			line:  "  abc  ",
			index: 6,
		},
		{
			line:  "",
			index: -1,
		},
	}

	for _, tt := range testCases {
		assert.Equal(t, tt.index, GetLastNonEmptyCharacterIndexInLine(tt.line))
	}
}
