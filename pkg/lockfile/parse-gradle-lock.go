package lockfile

import (
	"bufio"
	"fmt"
	"io"
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
	return parseFileAndPrintDiag(pathToLockfile, ParseGradleLockFile)
}

func ParseGradleLockFile(pathToLockfile string) ([]PackageDetails, Diagnostics, error) {
	return parseFile(pathToLockfile, ParseGradleLockWithDiagnostics)
}

func ParseGradleLockWithDiagnostics(r io.Reader) ([]PackageDetails, Diagnostics, error) {
	var diag Diagnostics

	pkgs := make([]PackageDetails, 0)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		lockLine := strings.TrimSpace(scanner.Text())
		if !isGradleLockFileDepLine(lockLine) {
			continue
		}

		pkg, err := parseToGradlePackageDetail(lockLine)
		if err != nil {
			diag.Warn(fmt.Sprintf("failed to parse lockline: %s", err.Error()))
			continue
		}

		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return []PackageDetails{}, diag, fmt.Errorf("failed to read: %w", err)
	}

	return pkgs, diag, nil
}
