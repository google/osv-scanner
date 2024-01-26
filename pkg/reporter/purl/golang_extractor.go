package purl

import (
	"log"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

func ExtractPURLFromGolang(packageInfo models.PackageInfo) (namespace string, name string, ok bool) {
	nameParts := strings.Split(packageInfo.Name, "/")
	if len(nameParts) == 0 || len(packageInfo.Name) == 0 {
		log.Printf("invalid golang package_name=%s", packageInfo.Name)
		ok = false

		return
	}
	ok = true
	if len(nameParts) > 1 {
		namespace = strings.Join(nameParts[:len(nameParts)-1], "/")
	}
	name = nameParts[len(nameParts)-1]

	return
}
