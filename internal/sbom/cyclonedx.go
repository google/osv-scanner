package sbom

import (
	"fmt"
	"io"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

type CycloneDX struct{}

var (
	cycloneDXTypes = []cyclonedx.BOMFileFormat{
		cyclonedx.BOMFileFormatJSON,
		cyclonedx.BOMFileFormatXML,
	}
)

func (c *CycloneDX) Name() string {
	return "CycloneDX"
}

func (c *CycloneDX) enumeratePackages(bom *cyclonedx.BOM, callback func(Identifier) error) error {
	for _, component := range *bom.Components {
		if component.PackageURL != "" {
			err := callback(Identifier{
				PURL: component.PackageURL,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *CycloneDX) GetPackages(r io.ReadSeeker, callback func(Identifier) error) error {
	var bom cyclonedx.BOM

	for _, formatType := range cycloneDXTypes {
		_, err := r.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek to start of file: %w", err)
		}
		decoder := cyclonedx.NewBOMDecoder(r, formatType)
		err = decoder.Decode(&bom)
		if err == nil && (bom.BOMFormat == "CycloneDX" || strings.HasPrefix(bom.XMLNS, "http://cyclonedx.org/schema/bom")) {
			return c.enumeratePackages(&bom, callback)
		}
	}
	return ErrInvalidFormat
}
