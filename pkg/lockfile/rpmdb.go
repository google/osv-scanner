package lockfile

import (
	"fmt"
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

		packages = append(packages, PackageDetails{
			Name:      rpmPkg.Name,
			Version:   rpmPkg.Version,
			Ecosystem: RedHatEcosystem,
			CompareAs: RedHatEcosystem,
		})
	}

	return packages, nil
}
