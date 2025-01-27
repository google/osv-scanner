package models

import (
	"encoding/xml"
	"strings"
	"unicode/utf8"
)

/*
StringHolder is a structure meant to deserialize string data along with the position of the data in the file when they can be mixed with other such as :
  - spaces, tabs and newline for formatting
  - comments (for example with XML based files)

It supports XML based files through the UnmarshalXML method
*/
type StringHolder struct {
	Value string
	FilePosition
}

func (stringHolder *StringHolder) computePositions(content, trimmedString string, lineStart, columnStart int) {
	// Lets compute where it starts
	stringStart := strings.Index(content, trimmedString)
	endOfLineCount := strings.Count(content[:stringStart], "\n")

	if !stringHolder.IsStartSet() {
		stringHolder.SetLineStart(lineStart + endOfLineCount)
	}
	stringHolder.SetLineEnd(lineStart + endOfLineCount)

	if endOfLineCount == 0 {
		// content is on the same line than tag start, we need to take the existing offset into account
		contentPrefixSize := utf8.RuneCountInString(content[:stringStart])
		if !stringHolder.IsStartSet() {
			stringHolder.SetColumnStart(columnStart + contentPrefixSize)
		}
		stringHolder.SetColumnEnd(columnStart + contentPrefixSize + len(trimmedString))
	} else {
		// content is not on the same line, column count is reset to 0
		contentLineStart := strings.LastIndex(content[:stringStart], "\n") + 1
		contentPrefixSize := utf8.RuneCountInString(content[contentLineStart:stringStart])

		if !stringHolder.IsStartSet() {
			stringHolder.SetColumnStart(contentPrefixSize + 1)
		}
		stringHolder.SetColumnEnd(contentPrefixSize + utf8.RuneCountInString(trimmedString) + 1)
	}
}

func (stringHolder *StringHolder) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	characterOffsetByLine := make(map[int]int) // We keep track of the offset caused by emojis line by line to correct character count with emojis
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch se := token.(type) {
		case xml.EndElement:
			if se.Name == start.Name {
				return nil
			}
		case xml.Comment:
			lines := strings.Split(string(se), "\n")
			for i, line := range lines {
				characterOffset := len(line) - utf8.RuneCountInString(line)
				characterOffsetByLine[lineStart+i] += characterOffset
			}
		case xml.CharData:
			content := string(se)
			trimmedString := strings.TrimSpace(content)
			if len(trimmedString) > 0 {
				// We have string content in there (not space, not a comment)
				stringHolder.Value += trimmedString
				runeColumnStart := columnStart - characterOffsetByLine[lineStart]
				stringHolder.computePositions(content, trimmedString, lineStart, runeColumnStart)
			}
		}
	}
}
