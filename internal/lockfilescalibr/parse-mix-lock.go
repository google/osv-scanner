package lockfilescalibr

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
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

const MixEcosystem Ecosystem = "Hex"

type MixLockExtractor struct{}

// Name of the extractor
func (e MixLockExtractor) Name() string { return "erlang/mixlock" }

// Version of the extractor
func (e MixLockExtractor) Version() int { return 0 }

func (e MixLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e MixLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "mix.lock"
}

func (e MixLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	re := cachedregexp.MustCompile(`^ +"(\w+)": \{.+,$`)

	scanner := bufio.NewScanner(input.Reader)

	var packages []*extractor.Inventory

	for scanner.Scan() {
		line := scanner.Text()

		match := re.FindStringSubmatch(line)

		if match == nil {
			continue
		}

		// we only care about the third and fourth "rows" which are both strings,
		// so we can safely split the line as if it's a set of comma-separated fields
		// even though that'll actually poorly represent nested arrays & objects
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ','
		})

		if len(fields) < 4 {
			_, _ = fmt.Fprintf(
				os.Stderr,
				"Found less than four fields when parsing a line that looks like a dependency in a mix.lock - please report this!\n",
			)

			continue
		}

		name := match[1]
		version := strings.TrimSpace(fields[2])
		commit := strings.TrimSpace(fields[3])

		version = strings.TrimSuffix(strings.TrimPrefix(version, `"`), `"`)
		commit = strings.TrimSuffix(strings.TrimPrefix(commit, `"`), `"`)

		if strings.HasSuffix(fields[0], ":git") {
			commit = version
			version = ""
		}

		packages = append(packages, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: commit,
			},
		})
	}

	if err := scanner.Err(); err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e MixLockExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeHex,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e MixLockExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e MixLockExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case MixLockExtractor:
		return string(MixEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = MixLockExtractor{}
