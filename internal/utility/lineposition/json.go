package lineposition

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/pkg/models"
)

func InJSON[P models.ILinePosition](groupKey string, dependencies map[string]P, lines []string, offset int) {
	var group, dependency string
	var groupLevel, stack int
	for lineNumber, line := range lines {
		position := lineNumber + offset + 1
		if strings.Contains(line, "{") {
			stack++
			keyRegexp := cachedregexp.MustCompile(`"(.+)"`)
			match := keyRegexp.FindStringSubmatch(line)
			if len(match) == 2 {
				key := match[1]
				if key != "" && group != "" {
					if stack == groupLevel+1 {
						if dep, ok := dependencies[key]; ok {
							dependency = key
							if os.Getenv("debug") == "true" {
								fmt.Fprintf(os.Stdout, "[DEPENDENCY][START] '%s' at line %d\n", dependency, position)
							}
							dep.SetStart(position)
							dependencies[dependency] = dep
						}
					}
				}
				if groupKey == key {
					if group == "" {
						if os.Getenv("debug") == "true" {
							fmt.Fprintf(os.Stdout, "[GROUP][START] '%s' at line %d\n", groupKey, position)
						}
						group = key
						groupLevel = stack
					} else {
						if dep, ok := dependencies[dependency]; ok {
							nestedDependencies := dep.GetNestedDependencies()
							if nestedDependencies != nil {
								if os.Getenv("debug") == "true" {
									fmt.Fprintf(os.Stdout, "[NESTED][START] At line %d\n", position)
								}
								InJSON(groupKey, nestedDependencies, lines[lineNumber:], position-1)
							}
						}
					}
				}
			}
		}
		if strings.Contains(line, "}") {
			stack--
			if group != "" {
				if stack == groupLevel {
					if dependency != "" {
						if dep, ok := dependencies[dependency]; ok {
							if os.Getenv("debug") == "true" {
								fmt.Fprintf(os.Stdout, "[DEPENDENCY][END] '%s' at line %d\n", dependency, position)
							}
							dep.SetEnd(position)
							dependencies[dependency] = dep
							dependency = ""
						}
					}
				} else if stack == groupLevel-1 {
					if os.Getenv("debug") == "true" {
						fmt.Fprintf(os.Stdout, "[GROUP][END] '%s' at line %d\n", groupKey, position)
					}
					group = ""
					if offset != 0 {
						if os.Getenv("debug") == "true" {
							fmt.Fprintf(os.Stdout, "[NESTED][END] At line %d\n", position)
						}

						return
					}
				}
			}
		}
	}
}
