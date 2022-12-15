package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	gradleLockFileCommentPrefix = "#"
	gradleLockFileEmptyPrefix   = "empty="
)

func isGradleLockFileDepLine(line string) bool {
	ret := strings.HasPrefix(line, gradleLockFileCommentPrefix) ||
		strings.HasPrefix(line, gradleLockFileEmptyPrefix)

	return !ret
}

func parseToGradlePackageDetail(line string) (PackageDetails, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return PackageDetails{}, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}

	group, artifact, version := parts[0], parts[1], parts[2]
	version = strings.SplitN(version, "=", 2)[0]

	return PackageDetails{
		Name:      fmt.Sprintf("%s:%s", group, artifact),
		Version:   version,
		Ecosystem: MavenEcosystem,
		CompareAs: MavenEcosystem,
	}, nil
}

func ParseGradleLock(pathToLockfile string) ([]PackageDetails, error) {
	lockFile, err := os.Open(pathToLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not open %s: %w", pathToLockfile, err)
	}

	defer lockFile.Close()

	pkgs := make([]PackageDetails, 0, 0)
	scanner := bufio.NewScanner(lockFile)

	for scanner.Scan() {
		lockLine := strings.TrimSpace(scanner.Text())
		if !isGradleLockFileDepLine(lockLine) {
			continue
		}

		pkg, err := parseToGradlePackageDetail(lockLine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse lockline: %s\n", err.Error())
			continue
		}

		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return []PackageDetails{}, fmt.Errorf("failed to read %s: %w", pathToLockfile, err)
	}

	return pkgs, nil
}
