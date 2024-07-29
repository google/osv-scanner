package lockfilescalibr

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

const YarnEcosystem = NpmEcosystem

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

// TODO: Extract source repo as well
func tryExtractCommit(resolution string) string {
	// language=GoRegExp
	matchers := []string{
		// ssh://...
		// git://...
		// git+ssh://...
		// git+https://...
		`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`,
		// https://....git/...
		`(?:^|.+@)https://.+\.git#(\w+)$`,
		`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`,
		`.+#commit[:=](\w+)$`,
		// github:...
		// gitlab:...
		// bitbucket:...
		`^(?:github|gitlab|bitbucket):.+#(\w+)$`,
	}

	for _, matcher := range matchers {
		re := cachedregexp.MustCompile(matcher)
		matched := re.FindStringSubmatch(resolution)

		if matched != nil {
			return matched[1]
		}
	}

	u, err := url.Parse(resolution)

	if err == nil {
		gitRepoHosts := []string{
			"bitbucket.org",
			"github.com",
			"gitlab.com",
		}

		for _, host := range gitRepoHosts {
			if u.Host != host {
				continue
			}

			if u.RawQuery != "" {
				queries := u.Query()

				if queries.Has("ref") {
					return queries.Get("ref")
				}
			}

			return u.Fragment
		}
	}

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
			Commit: tryExtractCommit(resolution),
		},
	}
}

type YarnLockExtractor struct{}

// Name of the extractor
func (e YarnLockExtractor) Name() string { return "javascript/yarnlock" }

// Version of the extractor
func (e YarnLockExtractor) Version() int { return 0 }

func (e YarnLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e YarnLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "yarn.lock"
}

func (e YarnLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
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
func (e YarnLockExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeNPM,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e YarnLockExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e YarnLockExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case YarnLockExtractor:
		return string(YarnEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = YarnLockExtractor{}
