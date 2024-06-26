package sbom

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

type CycloneDX struct{}

type cyclonedxType struct {
	name    string
	bomType cyclonedx.BOMFileFormat
}

var (
	cycloneDXTypes = []cyclonedxType{
		{
			name:    "json",
			bomType: cyclonedx.BOMFileFormatJSON,
		},
		{
			name:    "xml",
			bomType: cyclonedx.BOMFileFormatXML,
		},
	}
)

func (c *CycloneDX) Name() string {
	return "CycloneDX"
}

func (c *CycloneDX) MatchesRecognizedFileNames(path string) bool {
	// See https://cyclonedx.org/specification/overview/#recognized-file-patterns
	expectedGlobs := []string{
		"bom.xml",
		"bom.json",
		"*.cdx.json",
		"*.cdx.xml",
	}
	filename := filepath.Base(path)
	for _, v := range expectedGlobs {
		matched, err := filepath.Match(v, filename)
		if err != nil {
			// Just panic since the only error is invalid glob pattern
			panic("Glob pattern is invalid: " + err.Error())
		}

		if matched {
			return true
		}
	}

	return false
}

func (c *CycloneDX) enumerateComponents(components []cyclonedx.Component, callback func(Identifier) error) error {
	for _, component := range components {
		if component.PackageURL != "" {
			err := callback(Identifier{
				PURL: component.PackageURL,
			})
			if err != nil {
				return err
			}
		}
		// Components can have components, so enumerate them recursively.
		if component.Components != nil {
			err := c.enumerateComponents(*component.Components, callback)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *CycloneDX) enumeratePackages(bom *cyclonedx.BOM, callback func(Identifier) error) error {
	if bom.Components == nil {
		return nil
	}

	return c.enumerateComponents(*bom.Components, callback)
}

func (c *CycloneDX) GetPackages(r io.ReadSeeker, callback func(Identifier) error) error {
	//nolint:prealloc // Not sure how many there will be in advance.
	var errs []error
	var bom cyclonedx.BOM

	for _, formatType := range cycloneDXTypes {
		_, err := r.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek to start of file: %w", err)
		}
		decoder := cyclonedx.NewBOMDecoder(r, formatType.bomType)
		err = decoder.Decode(&bom)
		if err == nil {
			if bom.BOMFormat == "CycloneDX" || strings.HasPrefix(bom.XMLNS, "http://cyclonedx.org/schema/bom") {
				return c.enumeratePackages(&bom, callback)
			}

			err = errors.New("invalid BOMFormat")
		}

		errs = append(errs, fmt.Errorf("failed trying %s: %w", formatType.name, err))
	}

	return InvalidFormatError{
		Msg:  "failed to parse CycloneDX",
		Errs: errs,
	}
}
