package purl

import (
	"github.com/google/osv-scanner/pkg/models"
	"log"
	"strings"
)

func extractPURLFromMaven(packageInfo models.PackageInfo) (name string, namespace string, ok bool) {
	nameParts := strings.Split(packageInfo.Name, ":")
	if len(nameParts) != 2 {
		log.Printf("invalid maven package_name=%s", packageInfo.Name)
		return
	}
	ok = true
	namespace = nameParts[0]
	name = nameParts[1]
	return
}
