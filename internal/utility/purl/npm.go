package purl

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
)

func FromNpm(packageInfo models.PackageInfo) (namespace string, name string, err error) {
	if strings.HasPrefix(packageInfo.Name, "@") {
		nameParts := strings.Split(packageInfo.Name, "/")
		if len(nameParts) != 2 || nameParts[0] == "@" || nameParts[1] == "" {
			err = fmt.Errorf("invalid npm package_name (%s)", packageInfo.Name)

			return
		}
		namespace = nameParts[0]
		name = nameParts[1]

		return
	}

	if packageInfo.Name == "" || strings.Contains(packageInfo.Name, "/") {
		err = fmt.Errorf("invalid npm package_name (%s)", packageInfo.Name)

		return
	}

	name = packageInfo.Name

	return
}
