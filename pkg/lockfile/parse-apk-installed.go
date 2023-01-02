package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const AlpineEcosystem Ecosystem = "Alpine"

func ParseApkInstalled(pathToLockfile string) ([]PackageDetails, error) {
	var packages []PackageDetails

	file, err := os.Open(pathToLockfile)
	if err != nil {
		return packages, fmt.Errorf("could not open %s: %w", pathToLockfile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var curPkg PackageDetails = PackageDetails{}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// First line is empty or multiple empty lines, no current package values
			if (PackageDetails{}) == curPkg {
				continue
			}
			// Empty line follows a package info block. Append package before going to next one
			// If Package name is missing, record is invalid then skip
			if curPkg.Name == "" {
				_, _ = fmt.Fprintf(
					os.Stderr,
					"Warning: malformed APK installed file. Found no package name in record. File: %s\n",
					pathToLockfile,
				)
				curPkg = PackageDetails{}
				continue
			}
			if curPkg.Version == "" {
				_, _ = fmt.Fprintf(
					os.Stderr,
					"Warning: malformed APK installed file. Found no version number in record. File: %s\n",
					pathToLockfile,
				)
			}
			packages = append(packages, curPkg)
			curPkg = PackageDetails{}
			continue
		}
		// File SPECS: https://wiki.alpinelinux.org/wiki/Apk_spec
		if strings.HasPrefix(line, "P:") {
			curPkg.Name = strings.TrimPrefix(line, "P:")
			curPkg.Ecosystem = AlpineEcosystem
			curPkg.CompareAs = AlpineEcosystem
		} else if strings.HasPrefix(line, "V:") {
			curPkg.Version = strings.TrimPrefix(line, "V:")
		} else if strings.HasPrefix(line, "c:") {
			curPkg.Commit = strings.TrimPrefix(line, "c:")
		}

	}

	if (PackageDetails{}) != curPkg {
		if curPkg.Name == "" {
			_, _ = fmt.Fprintf(
				os.Stderr,
				"Warning: malformed APK installed file. Found no package name in record. File: %s\n",
				pathToLockfile,
			)
		} else {
			if curPkg.Version == "" {
				_, _ = fmt.Fprintf(
					os.Stderr,
					"Warning: malformed APK installed file. Found no version number in record. File: %s\n",
					pathToLockfile,
				)
			}
			packages = append(packages, curPkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", pathToLockfile, err)
	}

	return packages, nil
}
