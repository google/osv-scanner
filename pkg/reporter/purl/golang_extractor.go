package purl

import (
	"github.com/google/osv-scanner/pkg/models"
	"log"
	"strings"
)

func extractPURLFromGolang(packageInfo models.PackageInfo) (namespace string, name string, ok bool) {
	nameParts := strings.Split(packageInfo.Name, "/")
	if len(nameParts) < 2 {
		log.Printf("invalid golang package_name=%s", packageInfo.Name)
		return
	}
	ok = true
	namespace = strings.Join(nameParts[:len(nameParts)-1], "/")
	name = nameParts[len(nameParts)-1]
	return
}
