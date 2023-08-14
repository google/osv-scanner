package osvscanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/reporter"
)

// Get the go version of the default environment that osv-scanner is being ran on
func getGoVersion() (string, error) {
	// GOROOT will return either the custom go location specified by $GOROOT environment
	// variable, or it will return the default go location used during the go build,
	// which will match the default of the platform being ran on.
	versionBytes, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "VERSION"))
	if err != nil {
		return "", err
	}
	version := strings.TrimPrefix(string(versionBytes), "go")
	version, _, _ = strings.Cut(version, " ")

	return version, nil
}

func postLockfileEnricher(r reporter.Reporter, parsedLockfile *lockfile.Lockfile) {
	switch parsedLockfile.ParsedAs { //nolint:gocritic
	case "go.mod":
		goVer, err := getGoVersion()
		if err != nil {
			r.PrintError(fmt.Sprintf("cannot get go standard library version, go might not be installed: %s", err))
		}
		parsedLockfile.Packages = append(parsedLockfile.Packages, lockfile.PackageDetails{
			Name:      "stdlib",
			Version:   goVer,
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
		})
	}
}
