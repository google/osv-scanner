package results

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/models"
)

// Number of characters to display a git commit
const ShortCommitLen = 8

func PkgToString(pkgInfo models.PackageInfo) string {
	if pkgInfo.Commit != "" {
		if pkgInfo.Name != "" {
			// https://github.com/google/osv-scanner@12345678
			return fmt.Sprint(pkgInfo.Name, "@", pkgInfo.Commit[:ShortCommitLen])
		}
		// 1234567890abcdefghij1234567890abcdefghij
		return pkgInfo.Commit
	}

	// abc@v1.2.3
	return fmt.Sprint(pkgInfo.Name, "@", pkgInfo.Version)
}
