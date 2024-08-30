package yarnlock

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/internal"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

const YarnEcosystem = "npm"

func shouldSkipYarnLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

func groupYarnPackageLines(scanner *bufio.Scanner) [][]string {
	var groups [][]string
	var group []string

	for scanner.Scan() {
		line := scanner.Text()

		if shouldSkipYarnLine(line) {
			continue
		}

		// represents the start of a new dependency
		if !strings.HasPrefix(line, " ") {
			if len(group) > 0 {
				groups = append(groups, group)
			}
			group = make([]string, 0)
		}

		group = append(group, line)
	}

	if len(group) > 0 {
		groups = append(groups, group)
	}

	return groups
}

func extractYarnPackageName(str string) string {
	str = strings.TrimPrefix(str, "\"")
	str, _, _ = strings.Cut(str, ",")

	isScoped := strings.HasPrefix(str, "@")

	if isScoped {
		str = strings.TrimPrefix(str, "@")
	}

	name, right, _ := strings.Cut(str, "@")

	if strings.HasPrefix(right, "npm:") && strings.Contains(right, "@") {
		return extractYarnPackageName(strings.TrimPrefix(right, "npm:"))
	}

	if isScoped {
		name = "@" + name
	}

	return name
}

func determineYarnPackageVersion(group []string) string {
	re := cachedregexp.MustCompile(`^ {2}"?version"?:? "?([\w-.+]+)"?$`)

	for _, s := range group {
		matched := re.FindStringSubmatch(s)

		if matched != nil {
			return matched[1]
		}
	}

	// todo: decide what to do here - maybe panic...?
	return ""
}

func determineYarnPackageResolution(group []string) string {
	re := cachedregexp.MustCompile(`^ {2}"?(?:resolution:|resolved)"? "([^ '"]+)"$`)

	for _, s := range group {
		matched := re.FindStringSubmatch(s)

		if matched != nil {
			return matched[1]
		}
	}

	// todo: decide what to do here - maybe panic...?
	return ""
}

func parseYarnPackageGroup(group []string) *extractor.Inventory {
	name := extractYarnPackageName(group[0])
	version := determineYarnPackageVersion(group)
	resolution := determineYarnPackageResolution(group)

	if version == "" {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"Failed to determine version of %s while parsing a yarn.lock - please report this!\n",
			name,
		)
	}

	return &extractor.Inventory{
		Name:    name,
		Version: version,
		SourceCode: &extractor.SourceCodeIdentifier{
			Commit: internal.TryExtractCommit(resolution),
		},
	}
}

type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "javascript/yarnlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

func (e Extractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "yarn.lock"
}

func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)

	packageGroups := groupYarnPackageLines(scanner)

	if err := scanner.Err(); err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(packageGroups))

	for _, group := range packageGroups {
		if group[0] == "__metadata:" {
			continue
		}
		inv := parseYarnPackageGroup(group)
		inv.Locations = []string{input.Path}
		packages = append(packages, inv)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeNPM,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	return YarnEcosystem, nil
}

var _ filesystem.Extractor = Extractor{}
