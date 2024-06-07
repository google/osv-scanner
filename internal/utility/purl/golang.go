package purl

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

func FromGo(packageInfo models.PackageInfo) (namespace string, name string, err error) {
	nameParts := strings.Split(packageInfo.Name, "/")
	if len(nameParts) == 0 || len(packageInfo.Name) == 0 {
		err = fmt.Errorf("invalid golang package_name (%s)", packageInfo.Name)

		return
	}

	if len(nameParts) > 1 {
		namespace = strings.Join(nameParts[:len(nameParts)-1], "/")
	}
	name = nameParts[len(nameParts)-1]

	return
}
