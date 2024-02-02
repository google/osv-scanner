package reporter_test

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestEncoding_EncodeComponentsInValidCycloneDX1_4(t *testing.T) {
	var stdout, stderr strings.Builder
	cycloneDXReporter := reporter.NewCycloneDXReporter(&stdout, &stderr)
	vulnResults := models.VulnerabilityResults{
		Results: []models.PackageSource{
			{
				Source: models.SourceInfo{
					Path: "/path/to/lockfile.xml",
					Type: "",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "com.foo:the-greatest-package",
							Version:   "1.0.0",
							Ecosystem: string(models.EcosystemMaven),
							Start:     models.FilePosition{Line: 1},
							End:       models.FilePosition{Line: 3},
						},
					},
				},
			},
			{
				Source: models.SourceInfo{
					Path: "/path/to/npm/lockfile.lock",
					Type: "",
				},
				Packages: []models.PackageVulns{
					{
						Package: models.PackageInfo{
							Name:      "the-npm-package",
							Version:   "1.1.0",
							Ecosystem: string(models.EcosystemNPM),
							Start:     models.FilePosition{Line: 12},
							End:       models.FilePosition{Line: 15},
						},
					},
				},
			},
		},
	}

	// First we format packages in CycloneDX format
	err := cycloneDXReporter.PrintResult(&vulnResults)
	assert.Nil(t, err, "an error occured when formatting : %v", err)

	// Then we try to decode it using the CycloneDX library directly to check the content
	var bom cyclonedx.BOM
	decoder := cyclonedx.NewBOMDecoder(strings.NewReader(stdout.String()), cyclonedx.BOMFileFormatJSON)
	err = decoder.Decode(&bom)
	assert.Nil(t, err, "an error occured when decoding : %v", err)

	expectedBOM := cyclonedx.BOM{
		JSONSchema:  "http://cyclonedx.org/schema/bom-1.4.schema.json",
		Version:     1,
		BOMFormat:   cyclonedx.BOMFormat,
		SpecVersion: cyclonedx.SpecVersion1_4,
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "pkg:maven/com.foo/the-greatest-package@1.0.0",
				PackageURL: "pkg:maven/com.foo/the-greatest-package@1.0.0",
				Name:       "com.foo:the-greatest-package",
				Version:    "1.0.0",
			},
			{
				BOMRef:     "pkg:npm/the-npm-package@1.1.0",
				PackageURL: "pkg:npm/the-npm-package@1.1.0",
				Name:       "the-npm-package",
				Version:    "1.1.0",
			},
		},
	}
	assert.EqualValuesf(t, expectedBOM, bom, "Decoded bom is different than expected bom")
}
