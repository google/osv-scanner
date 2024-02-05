package lineposition

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
				openTOMLDependency(lineNumber, &open, dependencies[dependency])
			}
		}
	}
}

func openTOMLDependency[P models.IFilePosition](lineNumber int, open *bool, dep P) {
	position := lineNumber + 1
	dep.SetStart(position)
	*open = true
	if shouldDebugInTOML {
		name := reflect.Indirect(reflect.ValueOf(dep)).FieldByName("Name")
		_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][START] '%s' at line %d\n", name, position)
	}
}

func closeTOMLDependency[P models.IFilePosition](lineNumber int, open *bool, lines []string, dep P) {
	// Closing when new package/other section
	position := lineNumber
	// When last line
	if lineNumber == len(lines)-1 {
		position++
		// Skip empty lines
	} else if lines[lineNumber-1] == "" {
		position--
	}
	dep.SetEnd(position)
	*open = false
	if shouldDebugInTOML {
		name := reflect.Indirect(reflect.ValueOf(dep)).FieldByName("Name")
		_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][END] '%s' at line %d\n", name, position)
	}
}
