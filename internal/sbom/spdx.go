//nolint:nosnakecase
package sbom

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/rdfloader"
	"github.com/spdx/tools-golang/spdx/v2_3"
	"github.com/spdx/tools-golang/tvloader"
)

type SPDX struct{}
type spdxLoader func(io.Reader) (*v2_3.Document, error)

type loader struct {
	name   string
	loader spdxLoader
}

var (
	spdxLoaders = []loader{
		loader{
			name:   "json",
			loader: spdx_json.Load2_3,
		},
		loader{
			name:   "rdf",
			loader: rdfloader.Load2_3,
		},
		loader{
			name:   "tv",
			loader: tvloader.Load2_3,
		},
	}
)

func (s *SPDX) Name() string {
	return "SPDX"
}

func (s *SPDX) MatchesRecognizedFileNames(path string) bool {
	// All spdx files should have the .spdx in the filename, even if
	// it's not the extension:  https://spdx.github.io/spdx-spec/v2.3/conformance/
	return strings.Contains(strings.ToLower(filepath.Base(path)), ".spdx")
}

func (s *SPDX) enumeratePackages(doc *v2_3.Document, callback func(Identifier) error) error {
	for _, p := range doc.Packages {
		for _, r := range p.PackageExternalReferences {
			if r.RefType == "purl" {
				err := callback(Identifier{
					PURL: r.Locator,
				})
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (s *SPDX) GetPackages(r io.ReadSeeker, callback func(Identifier) error) error {
	var errs []error
	for _, loader := range spdxLoaders {
		_, err := r.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek to start of file: %w", err)
		}
		doc, err := loader.loader(r)
		if err == nil {
			return s.enumeratePackages(doc, callback)
		}
		errs = append(errs, fmt.Errorf("failed trying %s: %v", loader.name, err))
	}

	return &ErrInvalidFormat{
		msg:  "failed to parse SPDX",
		errs: errs,
	}
}
