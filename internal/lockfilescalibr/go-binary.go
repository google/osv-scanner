package lockfilescalibr

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/filesystem"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
)

type GoBinaryExtractor struct{}

// Name of the extractor
func (e GoBinaryExtractor) Name() string { return "go/gobinary" }

// Version of the extractor
func (e GoBinaryExtractor) Version() int { return 0 }

func (e GoBinaryExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e GoBinaryExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	if path == "" {
		return false
	}

	if strings.HasSuffix(path, string(filepath.Separator)) { // Don't extract directories
		return false
	}

	// If executable bit is not set for any owner/group/everyone, then it probably isn't a binary
	return fileInfo.Mode()&0111 != 0
}

func (e GoBinaryExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var readerAt io.ReaderAt
	if fileWithReaderAt, ok := input.Reader.(io.ReaderAt); ok {
		readerAt = fileWithReaderAt
	} else {
		buf := bytes.NewBuffer([]byte{})
		_, err := io.Copy(buf, input.Reader)
		if err != nil {
			return []*extractor.Inventory{}, err
		}
		readerAt = bytes.NewReader(buf.Bytes())
	}

	info, err := buildinfo.Read(readerAt)
	if err != nil {
		return []*extractor.Inventory{}, ErrIncompatibleFileFormat
	}

	pkgs := make([]*extractor.Inventory, 0, len(info.Deps)+1)
	pkgs = append(pkgs, &extractor.Inventory{
		Name:      "stdlib",
		Version:   strings.TrimPrefix(info.GoVersion, "go"),
		Locations: []string{input.Path},
	})

	for _, dep := range info.Deps {
		if dep.Replace != nil { // Use the replaced dep if it has been replaced
			dep = dep.Replace
		}
		pkgs = append(pkgs, &extractor.Inventory{
			Name:      dep.Path,
			Version:   strings.TrimPrefix(dep.Version, "v"),
			Locations: []string{input.Path},
		})
	}

	return pkgs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e GoBinaryExtractor) ToPURL(i *extractor.Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeGolang,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e GoBinaryExtractor) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }

func (e GoBinaryExtractor) Ecosystem(i *extractor.Inventory) (string, error) {
	switch i.Extractor.(type) {
	case GoBinaryExtractor:
		return "Go", nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ filesystem.Extractor = GoBinaryExtractor{}
