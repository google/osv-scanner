package osvscanner

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

// Get the go version of the default environment that osv-scanner is being ran on
func getGoVersion() (string, error) {
	versionBytes, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		return "", err
	}
	// version format can be:
	// - go1.20.6
	// - go1.22-20230729-RC00 cl/552016856 +457721cd52 X:fieldtrack,boringcrypto
	version := strings.TrimPrefix(string(versionBytes), "go")
	version, _, _ = strings.Cut(version, " ")

	return version, nil
}

func addCompilerVersion(r reporter.Reporter, parsedLockfile *lockfile.Lockfile) {
	switch parsedLockfile.ParsedAs { //nolint:gocritic
	case "go.mod":
		goVer, err := getGoVersion()
		if err != nil {
			r.PrintError(fmt.Sprintf("cannot get go standard library version, go might not be installed: %s\n", err))
		} else {
			parsedLockfile.Packages = append(parsedLockfile.Packages, lockfile.PackageDetails{
				Name:      "stdlib",
				Version:   goVer,
				Ecosystem: lockfile.GoEcosystem,
				CompareAs: lockfile.GoEcosystem,
			})
		}
	}
}
