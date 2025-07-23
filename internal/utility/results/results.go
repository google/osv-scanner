// Package results provides utility functions for working with scan results.
package results

import (
	"fmt"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// ShortCommitLen is the number of characters to display a git commit
const ShortCommitLen = 8

func PkgToString(pkgInfo models.PackageInfo) string {
	if pkgInfo.Commit != "" {
		if pkgInfo.Name != "" {
			// https://github.com/google/osv-scanner@12345678
			return fmt.Sprint(pkgInfo.Name, "@", GetShortCommit(pkgInfo.Commit))
		}
		// 1234567890abcdefghij1234567890abcdefghij
		return pkgInfo.Commit
	}

	// abc@v1.2.3
	return fmt.Sprint(pkgInfo.Name, "@", pkgInfo.Version)
}

func GetShortCommit(commit string) string {
	if len(commit) > ShortCommitLen {
		return commit[:ShortCommitLen]
	}

	return commit
}
