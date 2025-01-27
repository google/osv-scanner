package models

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringHolder_UnmarshalXML_ShouldFindValueAndPosition(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	type xmlFile struct {
		TestCase StringHolder `xml:"testCase"`
	}

	testCases := []struct {
		filename         string
		expectedPosition FilePosition
		expectedValue    string
	}{
		{
			filename:      "basic.xml",
			expectedValue: "value",
			expectedPosition: FilePosition{
				Line: Position{
					Start: 2,
					End:   2,
				},
				Column: Position{
					Start: 11,
					End:   16,
				},
			},
		},
		{
			filename:      "spaces.xml",
			expectedValue: "value",
			expectedPosition: FilePosition{
				Line: Position{
					Start: 2,
					End:   2,
				},
				Column: Position{
					Start: 16,
					End:   21,
				},
			},
		},
		{
			filename:      "tabs.xml",
			expectedValue: "value",
			expectedPosition: FilePosition{
				Line: Position{
					Start: 2,
					End:   2,
				},
				Column: Position{
					Start: 15,
					End:   20,
				},
			},
		},
		{
			filename:      "comments.xml",
			expectedValue: "value",
			expectedPosition: FilePosition{
				Line: Position{
					Start: 2,
					End:   3,
				},
				Column: Position{
					Start: 48,
					End:   29,
				},
			},
		},
		{
			filename:      "emoji.xml",
			expectedValue: "value",
			expectedPosition: FilePosition{
				Line: Position{
					Start: 3,
					End:   4,
				},
				Column: Position{
					Start: 48,
					End:   29,
				},
			},
		},
	}

	for _, tc := range testCases {
		testCase := tc
		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()
			parsed := xmlFile{}
			path := filepath.FromSlash(filepath.Join(dir, "fixtures/string_holder/"+testCase.filename))
			b, err := os.ReadFile(path)
			xmlDecoder := xml.NewDecoder(bytes.NewReader(b))

			if err != nil {
				t.Errorf("Got unexpected error: %v", err)
			}

			err = xmlDecoder.Decode(&parsed)
			if err != nil {
				t.Errorf("Got unexpected error: %v", err)
			}

			assert.Equal(t, testCase.expectedPosition.Line, parsed.TestCase.Line)
			assert.Equal(t, testCase.expectedPosition.Column, parsed.TestCase.Column)
			assert.Equal(t, testCase.expectedValue, parsed.TestCase.Value)
		})
	}
}
