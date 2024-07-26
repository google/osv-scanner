package lockfilescalibr

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
)

const (
	gradleLockFileCommentPrefix = "#"
	gradleLockFileEmptyPrefix   = "empty="
)

func isGradleLockFileDepLine(line string) bool {
	ret := strings.HasPrefix(line, gradleLockFileCommentPrefix) ||
		strings.HasPrefix(line, gradleLockFileEmptyPrefix)

	return !ret
}

func parseToGradlePackageDetail(line string) (*Inventory, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return &Inventory{}, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}

	group, artifact, version := parts[0], parts[1], parts[2]
	version = strings.SplitN(version, "=", 2)[0]

	return &Inventory{
		Name:    fmt.Sprintf("%s:%s", group, artifact),
		Version: version,
	}, nil
}

type GradleLockExtractor struct{}

// Name of the extractor
func (e GradleLockExtractor) Name() string { return "java/buildscriptgradlelockfile" }

// Version of the extractor
func (e GradleLockExtractor) Version() int { return 0 }

func (e GradleLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e GradleLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	base := filepath.Base(path)

	for _, lockfile := range []string{"buildscript-gradle.lockfile", "gradle.lockfile"} {
		if lockfile == base {
			return true
		}
	}

	return false
}

func (e GradleLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	pkgs := make([]*Inventory, 0)
	scanner := bufio.NewScanner(input.Reader)

	for scanner.Scan() {
		lockLine := strings.TrimSpace(scanner.Text())
		if !isGradleLockFileDepLine(lockLine) {
			continue
		}

		pkg, err := parseToGradlePackageDetail(lockLine)
		if err != nil {
			continue
		}

		pkg.Locations = []string{input.Path}

		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return []*Inventory{}, fmt.Errorf("failed to read: %w", err)
	}

	return pkgs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e GradleLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeMaven,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e GradleLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e GradleLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case GradleLockExtractor:
		return string(MavenEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = GradleLockExtractor{}
