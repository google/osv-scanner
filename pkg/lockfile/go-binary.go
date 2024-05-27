package lockfile

import (
	"bytes"
	"debug/buildinfo"
	"io"
	"log"
	"path/filepath"
	"strings"
)

// //nolint:gochecknoinits
// func init() {
// 	registerExtractor("go-binary", GoBinaryExtractor{})
// }

type GoBinaryExtractor struct{}

func (e GoBinaryExtractor) ShouldExtract(path string) bool {
	// Always return true on any non directory path, as a binary can be at any path
	return !strings.HasSuffix(path, string(filepath.Separator))
}

func (e GoBinaryExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var readerAt io.ReaderAt
	if fileWithReaderAt, ok := f.(io.ReaderAt); ok {
		readerAt = fileWithReaderAt
	} else {
		buf := bytes.NewBuffer([]byte{})
		_, err := io.Copy(buf, f)
		if err != nil {
			return []PackageDetails{}, err
		}
		readerAt = bytes.NewReader(buf.Bytes())
	}

	info, err := buildinfo.Read(readerAt)
	if err != nil {
		return []PackageDetails{}, err
	}
	log.Println(info.GoVersion)

	pkgs := make([]PackageDetails, 0, len(info.Deps)+1)
	pkgs = append(pkgs, PackageDetails{
		Name:      "stdlib",
		Version:   strings.TrimPrefix(info.GoVersion, "go"),
		Ecosystem: GoEcosystem,
		CompareAs: GoEcosystem,
	})

	for _, dep := range info.Deps {
		if dep.Replace != nil { // Use the replaced dep if it has been replaced
			dep = dep.Replace
		}
		pkgs = append(pkgs, PackageDetails{
			Name:      dep.Path,
			Version:   strings.TrimPrefix(dep.Version, "v"),
			Ecosystem: GoEcosystem,
			CompareAs: GoEcosystem,
		})
	}

	return pkgs, nil
}

var _ Extractor = GoBinaryExtractor{}
