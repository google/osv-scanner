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
			packages = append(packages, curPkg)
			curPkg = PackageDetails{}
			continue
		}
		// File SPECS: https://wiki.alpinelinux.org/wiki/Apk_spec
		if strings.HasPrefix(line, "P:") {
			curPkg.Name = strings.TrimPrefix(line, "P:")
		} else if strings.HasPrefix(line, "V:") {
			curPkg.Version = strings.TrimPrefix(line, "V:")
			curPkg.Ecosystem = AlpineEcosystem
			curPkg.CompareAs = AlpineEcosystem
		}

	}
	if (PackageDetails{}) != curPkg {
		packages = append(packages, curPkg)
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning %s: %w", pathToLockfile, err)
	}

	return packages, nil
}
