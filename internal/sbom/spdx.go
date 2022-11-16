package sbom

import (
	"io"

	"github.com/spdx/tools-golang/jsonloader"
	"github.com/spdx/tools-golang/rdfloader"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvloader"
)

type SPDX struct{}
type spdxLoader func(io.Reader) (*spdx.Document2_2, error)

var (
	spdxLoaders = []spdxLoader{
		jsonloader.Load2_2,
		rdfloader.Load2_2,
		tvloader.Load2_2,
	}
)

func (s *SPDX) Name() string {
	return "SPDX"
}

func (s *SPDX) enumeratePackages(doc *spdx.Document2_2, callback func(Identifier) error) error {
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
	for _, loader := range spdxLoaders {
		r.Seek(0, io.SeekStart)
		doc, err := loader(r)
		if err == nil {
			return s.enumeratePackages(doc, callback)
		}
	}
	return InvalidFormat
}
