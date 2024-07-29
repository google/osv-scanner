package lockfilescalibr

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
)

const PipEcosystem Ecosystem = "PyPI"

// todo: expand this to support more things, e.g.
//
//	https://pip.pypa.io/en/stable/reference/requirements-file-format/#example
func parseLine(line string) *extractor.Inventory {
	var constraint string
	name := line

	version := "0.0.0"

	if strings.Contains(line, "==") {
		constraint = "=="
	}

	if strings.Contains(line, ">=") {
		constraint = ">="
	}

	if strings.Contains(line, "~=") {
		constraint = "~="
	}

	if strings.Contains(line, "!=") {
		constraint = "!="
	}

	if constraint != "" {
		unprocessedName, unprocessedVersion, _ := strings.Cut(line, constraint)
		name = strings.TrimSpace(unprocessedName)

		if constraint != "!=" {
			version, _, _ = strings.Cut(strings.TrimSpace(unprocessedVersion), " ")
		}
	}

	return &extractor.Inventory{
		Name:    normalizedRequirementName(name),
		Version: version,
		Metadata: othermetadata.DepGroupMetadata{
			DepGroupVals: []string{},
		},
	}
}

// normalizedName ensures that the package name is normalized per PEP-0503
// and then removing "added support" syntax if present.
//
// This is done to ensure we don't miss any advisories, as while the OSV
// specification says that the normalized name should be used for advisories,
// that's not the case currently in our databases, _and_ Pip itself supports
// non-normalized names in the requirements.txt, so we need to normalize
// on both sides to ensure we don't have false negatives.
//
// It's possible that this will cause some false positives, but that is better
// than false negatives, and can be dealt with when/if it actually happens.
func normalizedRequirementName(name string) string {
	// per https://www.python.org/dev/peps/pep-0503/#normalized-names
	name = cachedregexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, "[")

	return name
}

func removeComments(line string) string {
	var re = cachedregexp.MustCompile(`(^|\s+)#.*$`)

	return strings.TrimSpace(re.ReplaceAllString(line, ""))
}

func isNotRequirementLine(line string) bool {
	return line == "" ||
		// flags are not supported
		strings.HasPrefix(line, "-") ||
		// file urls
		strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "http://") ||
		// file paths are not supported (relative or absolute)
		strings.HasPrefix(line, ".") ||
		strings.HasPrefix(line, "/")
}

func isLineContinuation(line string) bool {
	// checks that the line ends with an odd number of back slashes,
	// meaning the last one isn't escaped
	var re = cachedregexp.MustCompile(`([^\\]|^)(\\{2})*\\$`)

	return re.MatchString(line)
}

type RequirementsTxtExtractor struct{}

// Name of the extractor
func (e RequirementsTxtExtractor) Name() string { return "python/requirementstxt" }

// Version of the extractor
func (e RequirementsTxtExtractor) Version() int { return 0 }

func (e RequirementsTxtExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e RequirementsTxtExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "requirements.txt"
}

func (e RequirementsTxtExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "requirements.txt"
}

func (e RequirementsTxtExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventories, err := parseRequirementsTxt(input, map[string]struct{}{})

	if err != nil {
		return []*extractor.Inventory{}, err
	}

	// TODO: This currently matches the existing behavior
	// ideally we should add the locations of the -r requirement files as well
	// to the locations list
	for i := range inventories {
		inventories[i].Locations = []string{input.Path}
	}

	return inventories, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e RequirementsTxtExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypePyPi,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e RequirementsTxtExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) {
	return []string{}, nil
}

func (e RequirementsTxtExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case RequirementsTxtExtractor:
		return string(PipEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

func parseRequirementsTxt(input *filesystem.ScanInput, requiredAlready map[string]struct{}) ([]*extractor.Inventory, error) {
	inventories := map[string]*extractor.Inventory{}

	group := strings.TrimSuffix(filepath.Base(input.Path), filepath.Ext(input.Path))
	hasGroup := func(groups []string) bool {
		for _, g := range groups {
			if g == group {
				return true
			}
		}

		return false
	}

	scanner := bufio.NewScanner(input.Reader)
	for scanner.Scan() {
		line := scanner.Text()

		for isLineContinuation(line) {
			line = strings.TrimSuffix(line, "\\")

			if scanner.Scan() {
				line += scanner.Text()
			}
		}

		line = removeComments(line)
		if ar := strings.TrimPrefix(line, "-r "); ar != line {
			fullReqPath := filepath.Join(filepath.Dir(input.Path), ar)
			err := func() error {
				if _, ok := requiredAlready[fullReqPath]; ok {
					return nil
				}
				af, err := input.FS.Open(fullReqPath)

				if err != nil {
					return fmt.Errorf("failed to include %s: %w", line, err)
				}

				defer af.Close()

				info, err := af.Stat()
				if err != nil {
					return fmt.Errorf("failed to include %s: %w", line, err)
				}

				requiredAlready[fullReqPath] = struct{}{}
				newScanInput := filesystem.ScanInput{
					FS:       input.FS,
					Path:     fullReqPath,
					ScanRoot: input.ScanRoot,
					Reader:   af,
					Info:     info,
				}

				details, err := parseRequirementsTxt(&newScanInput, requiredAlready)

				if err != nil {
					return fmt.Errorf("failed to include %s: %w", line, err)
				}

				for _, detail := range details {
					inventories[detail.Name+"@"+detail.Version] = detail
				}

				return nil
			}()

			if err != nil {
				return []*extractor.Inventory{}, err
			}

			continue
		}

		if isNotRequirementLine(line) {
			continue
		}

		inv := parseLine(line)

		key := inv.Name + "@" + inv.Version
		if _, ok := inventories[key]; !ok {
			inventories[key] = inv
		}

		d := inventories[key]

		// Metadata will always be othermetadata.DepGroupMetadata, as that is what we construct at the
		// start of this file
		existingGroups := d.Metadata.(othermetadata.DepGroups).DepGroups()
		if !hasGroup(existingGroups) {
			d.Metadata = othermetadata.DepGroupMetadata{
				DepGroupVals: append(existingGroups, group),
			}
			inventories[key] = d
		}
	}

	if err := scanner.Err(); err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return maps.Values(inventories), nil
}

var _ filesystem.Extractor = RequirementsTxtExtractor{}
