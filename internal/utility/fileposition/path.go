package fileposition

import (
	"os"
	"path/filepath"
	"strings"
)

func RemoveHostPath(scanPath string, packagePath string, considerScanPathAsRoot bool, pathRelativeToScanDir bool) string {
	if !(considerScanPathAsRoot || pathRelativeToScanDir) {
		return packagePath
	}

	hostPath, err := filepath.Abs(scanPath)
	if err != nil {
		return packagePath
	}
	stats, err := os.Lstat(hostPath)
	if err != nil {
		return packagePath
	}
	if !stats.IsDir() {
		hostPath = filepath.Dir(hostPath)
	}

	path := filepath.ToSlash(strings.TrimPrefix(packagePath, hostPath))
	if pathRelativeToScanDir {
		path = strings.TrimPrefix(path, "/")
	}

	return path
}
