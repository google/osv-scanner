package lockfile

import (
	"fmt"
	"io"
	"os"

	_ "github.com/glebarez/go-sqlite"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

const RedHatEcosystem Ecosystem = "Redhat"

func ParseRpmDB(pathToLockfile string) ([]PackageDetails, error) {
	db, err := rpmdb.Open(pathToLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not open %s: %w", pathToLockfile, err)
	}
	pkgList, err := db.ListPackages()
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("error listing packages from %s: %w", pathToLockfile, err)
	}

	packages := make([]PackageDetails, 0, len(pkgList))

	for _, rpmPkg := range pkgList {
		// {Epoch:0 Name:m4 Version:1.4.16 Release:10.el7 Arch:x86_64}
		// {Epoch:0 Name:zip Version:3.0 Release:11.el7 Arch:x86_64}
		// ...
		if rpmPkg.Name == "" {
			_, _ = fmt.Fprintf(
				os.Stderr,
				"warning: malformed RPM DB. Found empty package name. File: %s\n",
				pathToLockfile,
			)

			continue
		}

		var pkg = PackageDetails{
			Ecosystem: RedHatEcosystem,
			CompareAs: RedHatEcosystem,
		}
		pkg.Name = rpmPkg.Name
		pkg.Version = rpmPkg.Version
		packages = append(packages, pkg)
	}

	return packages, nil
}

// Create temporary file from ReadCloser object, then pass its path to standard parse function
func ParseRpmDBFromReader(file io.ReadCloser, pathToLockfile string) ([]PackageDetails, error) {
	// TODO: Use random string in filename to avoid collision in parallel runs on same system
	tempFile, err := os.CreateTemp("", "osv-scanner-rpmdb")
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("failed to create temp rpmdb file: %w", err)
	}

	defer func() {
		err = os.Remove(tempFile.Name())
		if err != nil {
			_, _ = fmt.Fprintf(
				os.Stderr,
				"error: failed to remove temp rpmdb file:  %+v\n",
				err,
			)
		}
	}()

	_, err = io.Copy(tempFile, file)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("failed to copy rpmdb contents to temp file: %w", err)
	}

	return ParseRpmDB(tempFile.Name())
}
