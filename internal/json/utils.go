package json

import (
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

/*
GetSectionOffset computes the start line of any section in the file.
To see the regex in action, check out https://regex101.com/r/3EHqB8/1 (it uses the dependencies section as an example)
It matches lines like this:

	"dependencies": {
*/
func GetSectionOffset(sectionName string, content string) int {
	sectionMatcher := cachedregexp.MustCompile(`(?m)^\s*"` + cachedregexp.QuoteMeta(sectionName) + `":\s*{\s*$`)
	sectionIndex := sectionMatcher.FindStringIndex(content)
	if len(sectionIndex) < 2 {
		return -1
	}

	return strings.Count(content[:sectionIndex[1]], "\n")
}

/*
ExtractPackageIndexes find where a package is defined in a json source file. It returns the block indexes along with
name and version. It assumes:
 1. the package won't be declared twice in the same block
 2. the declaration will be shaped as "<package name>" : "<version or constraints>"

# If no targeted version is passed, it will search for any version

You can see the regex in action here: https://regex101.com/r/zzrEAh/1
It matches the following:
"@typescript-eslint/eslint-plugin": "^5.12.0",
"test": "3"

The expected result of FindAllStringSubmatchIndex is a [6]int, with the following structure :
- index 0/1 represents block start/end
- index 2/3 represents name start/end
- index 4/5 represents version start/end
*/
func ExtractPackageIndexes(pkgName, targetedVersion, content string) []int {
	var versionRegex string

	if len(targetedVersion) == 0 {
		versionRegex = ".*"
	} else {
		versionRegex = cachedregexp.QuoteMeta(targetedVersion)
	}
	pkgMatcher := cachedregexp.MustCompile(`"(?P<pkgName>` + pkgName + `)\"\s*:\s*\"(?P<version>` + versionRegex + `)"`)
	result := pkgMatcher.FindAllStringSubmatchIndex(content, -1)

	if len(result) == 0 || len(result[0]) < 6 {
		return []int{}
	}

	return result[0]
}
