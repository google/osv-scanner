package lineposition

import (
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/pkg/models"
)

func InJSON[P models.ILinePosition](groupKey string, dependencies map[string]P, lines []string, offset int) {
	var group, dependency string
	var groupLevel, stack int
	for lineNumber, line := range lines {
		if strings.Contains(line, "{") {
			stack++
			keyRegexp := cachedregexp.MustCompile(`"(.+)"`)
			match := keyRegexp.FindStringSubmatch(line)
			if len(match) == 2 {
				key := match[1]
				if group != "" {
					if stack == groupLevel+1 {
						if dep, ok := dependencies[key]; ok {
							// Start line of a dependency
							dependency = key
							dep.SetStart(models.FilePosition{Line: lineNumber + offset + 1})
							dependencies[dependency] = dep
						}
					}
				}
				if groupKey == key {
					if group == "" {
						// Start line of a group
						group = key
						groupLevel = stack
					} else {
						if dep, ok := dependencies[dependency]; ok {
							// Nested groupKey
							nestedDependencies := dep.GetNestedDependencies()
							if nestedDependencies != nil {
								// Handling nested dependencies
								InJSON(groupKey, nestedDependencies, lines[lineNumber:], lineNumber)
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
					if dep, ok := dependencies[dependency]; ok {
						// End line of a dependency
						dep.SetEnd(models.FilePosition{Line: lineNumber + offset + 1})
						dependencies[dependency] = dep
						dependency = ""
					}
				} else if stack == groupLevel-1 {
					// End line of a group
					group = ""
					if offset != 0 {
						// End of nested dependencies
						return
					}
				}
			}
		}
	}
}
