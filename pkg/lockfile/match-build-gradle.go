package lockfile

import (
	"io"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"
)

type BuildGradleMatcher struct{}

func (m BuildGradleMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	fileName := "build.gradle"

	// lockfile (default, groovy)
	sourcefile, err := lockfile.Open(fileName)
	if err != nil {
		// kotlin
		sourcefile, err = lockfile.Open(fileName + ".kts")
	}

	// gradle verification metadata (<rootdir>/gradle/verification-metadata.xml)
	relativePath := "../" + fileName
	if err != nil {
		// groovy
		sourcefile, err = lockfile.Open(relativePath)
	}
	if err != nil {
		// kotlin
		sourcefile, err = lockfile.Open(relativePath + ".kts")
	}

	return sourcefile, err
}

func (m BuildGradleMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	for index, line := range lines {
		lineNumber := index + 1
		for key, pkg := range packages {
			group, artifact, _ := strings.Cut(pkg.Name, ":")
			// TODO: what to do if, while using extended format, components are split in multiple lines?
			if strings.Contains(line, group) && strings.Contains(line, artifact) {
				scope := m.extractScope(line)
				if len(scope) > 0 {
					packages[key].DepGroups = append(packages[key].DepGroups, scope)
				}

				if strings.Contains(line, pkg.Version) {
					startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
					endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

					packages[key].BlockLocation = models.FilePosition{
						Line:     models.Position{Start: lineNumber, End: lineNumber},
						Column:   models.Position{Start: startColumn, End: endColumn},
						Filename: sourcefile.Path(),
					}

					nameLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, artifact, lineNumber, "['\":]", "['\":]")
					if nameLocation != nil {
						nameLocation.Filename = sourcefile.Path()
						packages[key].NameLocation = nameLocation
					}

					versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, pkg.Version, lineNumber, "['\":]", "['\"]")
					if versionLocation != nil {
						versionLocation.Filename = sourcefile.Path()
						packages[key].VersionLocation = versionLocation
					}
				}
			}
		}
	}

	return nil
}

/*
This is based on https://docs.gradle.org/current/userguide/dependency_configurations.html#sub:what-are-dependency-configurations
We extract a runtimeClasspath scope when we find a runtime only instruction because it will only appear as "testRuntimeClasspath" in the lockfile

This let us make the difference between a testRuntime dependency and a runtime only dependency
*/
func (m BuildGradleMatcher) extractScope(line string) string {
	var instruction string
	if strings.Contains(line, "(") {
		instruction = strings.TrimSpace(strings.Split(line, "(")[0])
	} else {
		instruction = strings.TrimSpace(strings.Fields(line)[0])
	}

	if instruction == "runtimeOnly" {
		return "runtimeClasspath"
	}

	return ""
}

var _ Matcher = BuildGradleMatcher{}
