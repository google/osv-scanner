package lineposition

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/pkg/models"
)

var debug bool

func InJSON[P models.IFilePosition](groupKey string, dependencies map[string]P, lines []string, offset int) {
	debug = os.Getenv("debug") == "true"
	var group, dependency string
	var groupLevel, stack int

	for lineNumber, line := range lines {
		position := lineNumber + offset
		if strings.Contains(line, "{") {
			stack++
			if key := retrieveKeyFromLine(line); key != "" {
				if group != "" && stack == groupLevel+1 {
					openDependency(key, dependencies, position, &dependency)
				}
				if groupKey == key {
					if group == "" {
						openGroup(key, stack, position, &group, &groupLevel)
					} else if dep, ok := dependencies[dependency]; ok {
						handleNestedDependencies(lines, groupKey, dep, position)
					}
				}
			}
		}
		if strings.Contains(line, "}") {
			stack--
			if group != "" {
				if stack == groupLevel {
					if dependency != "" {
						closeDependency(dependencies, position, &dependency)
					}
				} else if stack == groupLevel-1 {
					closeGroup(position, &group)
					if offset != 0 {
						if debug {
							_, _ = fmt.Fprintf(os.Stdout, "[NESTED][END] At line %d\n", position)
						}

						return
					}
				}
			}
		}
	}
}

func retrieveKeyFromLine(line string) string {
	keyRegexp := cachedregexp.MustCompile(`"(.+)"`)
	match := keyRegexp.FindStringSubmatch(line)
	if len(match) == 2 {
		return match[1]
	} else {
		return ""
	}
}

func openDependency[P models.IFilePosition](key string, dependencies map[string]P, position int, dependency *string) {
	if dep, ok := dependencies[key]; ok {
		*dependency = key
		dep.SetStart(position + 1)
		dependencies[*dependency] = dep
		if debug {
			_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][START] '%s' at line %d\n", *dependency, position+1)
		}
	}
}

func closeDependency[P models.IFilePosition](dependencies map[string]P, position int, dependency *string) {
	if dep, ok := dependencies[*dependency]; ok {
		dep.SetEnd(position + 1)
		dependencies[*dependency] = dep
		*dependency = ""
		if debug {
			_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][END] '%s' at line %d\n", *dependency, position+1)
		}
	}
}

func openGroup(key string, stack int, position int, group *string, groupLevel *int) {
	*group = key
	*groupLevel = stack
	if debug {
		_, _ = fmt.Fprintf(os.Stdout, "[GROUP][START] '%s' at line %d\n", *group, position+1)
	}
}

func closeGroup(position int, group *string) {
	*group = ""
	if debug {
		_, _ = fmt.Fprintf(os.Stdout, "[GROUP][END] '%s' at line %d\n", *group, position)
	}
}

func handleNestedDependencies[P models.IFilePosition](lines []string, groupKey string, dep P, position int) {
	nestedDependencies := dep.GetNestedDependencies()
	if nestedDependencies != nil {
		if debug {
			_, _ = fmt.Fprintf(os.Stdout, "[NESTED][START] At line %d\n", position+1)
		}
		InJSON(groupKey, nestedDependencies, lines[position:], position)
	}
}
