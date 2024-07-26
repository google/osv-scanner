package lockfilescalibr

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
)

type GoBinaryExtractor struct{}

// Name of the extractor
func (e GoBinaryExtractor) Name() string { return "go/gobinary" }

// Version of the extractor
func (e GoBinaryExtractor) Version() int { return 0 }

func (e GoBinaryExtractor) Requirements() Requirements {
	return Requirements{}
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

func (e GoBinaryExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var readerAt io.ReaderAt
	if fileWithReaderAt, ok := input.Reader.(io.ReaderAt); ok {
		readerAt = fileWithReaderAt
	} else {
		buf := bytes.NewBuffer([]byte{})
		_, err := io.Copy(buf, input.Reader)
		if err != nil {
			return []*Inventory{}, err
		}
		readerAt = bytes.NewReader(buf.Bytes())
	}

	info, err := buildinfo.Read(readerAt)
	if err != nil {
		return []*Inventory{}, ErrIncompatibleFileFormat
	}

	pkgs := make([]*Inventory, 0, len(info.Deps)+1)
	pkgs = append(pkgs, &Inventory{
		Name:      "stdlib",
		Version:   strings.TrimPrefix(info.GoVersion, "go"),
		Locations: []string{input.Path},
	})

	for _, dep := range info.Deps {
		if dep.Replace != nil { // Use the replaced dep if it has been replaced
			dep = dep.Replace
		}
		pkgs = append(pkgs, &Inventory{
			Name:      dep.Path,
			Version:   strings.TrimPrefix(dep.Version, "v"),
			Locations: []string{input.Path},
		})
	}

	return pkgs, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e GoBinaryExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeGolang,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e GoBinaryExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e GoBinaryExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case GoBinaryExtractor:
		return string(GoEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = GoBinaryExtractor{}
