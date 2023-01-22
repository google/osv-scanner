package lockfile

import "io"

type OSPkgMgrDetailsParser = func(file io.ReadCloser, pathToLockfile string) ([]PackageDetails, error)

// PkgMgrParse maps package manager to its parser function
var PkgMgrParse = map[string]OSPkgMgrDetailsParser{
	"apk":  ParseApkInstalledFromReader,
	"dpkg": ParseDpkgStatusFromReader,
}

// Docker Image OS info
type ImageOS struct {
	Name             string // e.g. Debian
	Version          string // OS release
	PkgMgr           string // Package Mgr name e.g. dpkg
	PkgMgrDBLocation string // Package manager DB location on filesystem
}
