package purl

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
)

func FromMaven(packageInfo models.PackageInfo) (namespace string, name string, err error) {
	nameParts := strings.Split(packageInfo.Name, ":")
	if len(nameParts) != 2 {
		err = fmt.Errorf("invalid maven package_name(%s)", packageInfo.Name)
		return
	}
	namespace = nameParts[0]
	name = nameParts[1]

	return
}
