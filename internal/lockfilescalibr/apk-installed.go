package lockfilescalibr

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

const AlpineEcosystem Ecosystem = "Alpine"

func groupApkPackageLines(scanner *bufio.Scanner) [][]string {
	var groups [][]string
	var group []string

	for scanner.Scan() {
		line := scanner.Text()

		if line != "" {
			group = append(group, line)
			continue
		}
		if len(group) > 0 {
			groups = append(groups, group)
		}
		group = make([]string, 0)
	}

	if len(group) > 0 {
		groups = append(groups, group)
	}

	return groups
}

func parseApkPackageGroup(group []string) *Inventory {
	var pkg = &Inventory{
		SourceCode: &SourceCodeIdentifier{},
	}

	// File SPECS: https://wiki.alpinelinux.org/wiki/Apk_spec
	for _, line := range group {
		switch {
		case strings.HasPrefix(line, "P:"):
			pkg.Name = strings.TrimPrefix(line, "P:")
		case strings.HasPrefix(line, "V:"):
			pkg.Version = strings.TrimPrefix(line, "V:")
		case strings.HasPrefix(line, "c:"):
			pkg.SourceCode.Commit = strings.TrimPrefix(line, "c:")
		}
	}

	return pkg
}

type ApkInstalledExtractor struct{}

// Name of the extractor
func (e ApkInstalledExtractor) Name() string { return "alpine/apk-installed" }

// Version of the extractor
func (e ApkInstalledExtractor) Version() int { return 0 }

func (e ApkInstalledExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e ApkInstalledExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return path == "lib/apk/db/installed"
}

func (e ApkInstalledExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)

	packageGroups := groupApkPackageLines(scanner)

	inventories := make([]*Inventory, 0, len(packageGroups))

	for _, group := range packageGroups {
		pkg := parseApkPackageGroup(group)

		if pkg.Name == "" {
			continue
		}

		pkg.Locations = []string{input.Path}
		inventories = append(inventories, pkg)
	}

	alpineVersion, alpineVerErr := alpineReleaseExtractor(input.FS)
	if alpineVerErr == nil { // TODO: Log error? We might not be on a alpine system
		for i := range inventories {
			inventories[i].Metadata = DistroVersionMetadata{
				DistroVersionStr: alpineVersion,
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return inventories, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return inventories, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e ApkInstalledExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:      packageurl.TypeApk,
		Name:      i.Name,
		Version:   i.Version,
		Namespace: "alpine",
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e ApkInstalledExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e ApkInstalledExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case ApkInstalledExtractor:
		if i.Metadata != nil {
			return string(AlpineEcosystem) + ":" + i.Metadata.(DistroVersionMetadata).DistroVersionStr, nil
		} else {
			return string(AlpineEcosystem), nil
		}
	default:
		return "", ErrWrongExtractor
	}
}

// alpineReleaseExtractor extracts the release version for an alpine distro
// will return "" if no release version can be found, or if distro is not alpine
func alpineReleaseExtractor(opener plugin.FS) (string, error) {
	alpineReleaseFile, err := opener.Open("etc/alpine-release")
	if err != nil {
		return "", err
	}
	defer alpineReleaseFile.Close()

	// Read to string
	buf := new(strings.Builder)
	_, err = io.Copy(buf, alpineReleaseFile)
	if err != nil {
		return "", err
	}

	// We only care about the major and minor version
	// because that's the Alpine version that advisories are published against
	//
	// E.g. 3.20.0_alpha20231219  --->  v3.20
	valueSplit := strings.Split(buf.String(), ".")
	returnVersion := "v" + valueSplit[0] + "." + valueSplit[1]

	return returnVersion, nil
}

var _ Extractor = ApkInstalledExtractor{}
