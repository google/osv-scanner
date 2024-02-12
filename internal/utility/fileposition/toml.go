package fileposition

import (
	"fmt"
	"os"
	"reflect"

	"github.com/google/osv-scanner/pkg/models"
)

var shouldDebugInTOML bool

func InTOML[P models.IFilePosition](groupKey string, otherKey string, dependencies []P, lines []string) {
	shouldDebugInTOML = os.Getenv("debug") == "true"
	dependency := 0
	open := false
	for lineNumber, line := range lines {
		if line == groupKey || line == otherKey || (lineNumber == len(lines)-1) {
			if open {
				closeTOMLDependency(lineNumber, &open, lines, dependencies[dependency])
				dependency++
			}
		}
		if line == groupKey {
			if !open {
				openTOMLDependency(lineNumber, line, &open, dependencies[dependency])
			}
		}
	}
}

func openTOMLDependency[P models.IFilePosition](lineNumber int, line string, open *bool, dep P) {
	lineStart := lineNumber + 1
	columnStart := GetFirstNonEmptyCharacterIndexInLine(line)
	dep.SetLineStart(lineStart)
	dep.SetColumnStart(columnStart)
	*open = true
	if shouldDebugInTOML {
		name := reflect.Indirect(reflect.ValueOf(dep)).FieldByName("Name")
		_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][START] '%s' at line %d, column %d\n", name, lineStart, columnStart)
	}
}

func closeTOMLDependency[P models.IFilePosition](lineNumber int, open *bool, lines []string, dep P) {
	// Closing when new package/other section
	lineEnd := lineNumber
	// When last line
	if lineNumber == len(lines)-1 {
		lineEnd++
		// Skip empty lines
	} else if lines[lineNumber-1] == "" {
		lineEnd--
	}
	columnEnd := GetLastNonEmptyCharacterIndexInLine(lines[lineEnd-1])
	dep.SetLineEnd(lineEnd)
	dep.SetColumnEnd(columnEnd)
	*open = false
	if shouldDebugInTOML {
		name := reflect.Indirect(reflect.ValueOf(dep)).FieldByName("Name")
		_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][END] '%s' at line %d, column %d\n", name, lineEnd, columnEnd)
	}
}
