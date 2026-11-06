// Package output provides functionality for printing scan results in various formats.
package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/internal/output/sbom"
	"github.com/google/osv-scanner/v2/internal/utility/purl"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// PrintCycloneDXResults writes results to the provided writer in CycloneDX format
func PrintCycloneDXResults(vulnResult *models.VulnerabilityResults, cycloneDXVersion models.CycloneDXVersion, outputWriter io.Writer) error {
	resultsByPurl, errs := purl.Group(vulnResult.Results)

	bom, err := convertBOM(sbom.BuildCycloneDXBom(resultsByPurl), sbom.SpecVersionToSpecVersion[cycloneDXVersion])

	if err == nil {
		encoder := cyclonedx.NewBOMEncoder(outputWriter, cyclonedx.BOMFileFormatJSON)
		encoder.SetPretty(true)

		err = encoder.Encode(bom)
	}

	return errors.Join(err, errors.Join(errs...))
}

// convertBOM returns a copy of the given BOM that adheres to the given spec version.
//
// cyclonedx-go only exposes its conversion via EncodeVersion, which deep-copies
// the BOM using encoding/gob before converting it; gob does not transmit zero
// values, so pointers to zero (such as a CVSS score of 0.0) are lost.
//
// To work around this, we encode the converted BOM, decode it again, and then
// restore the values that were lost from the original BOM.
//
// todo: remove once https://github.com/CycloneDX/cyclonedx-go/issues/304 is fixed
func convertBOM(bom *cyclonedx.BOM, specVersion cyclonedx.SpecVersion) (*cyclonedx.BOM, error) {
	var buf bytes.Buffer

	if err := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON).EncodeVersion(bom, specVersion); err != nil {
		return nil, err
	}

	var converted cyclonedx.BOM

	if err := json.Unmarshal(buf.Bytes(), &converted); err != nil {
		return nil, err
	}

	restoreScores(bom, &converted)

	return &converted, nil
}

// restoreScores copies vulnerability rating scores from the original BOM into
// the converted BOM, where they were dropped during conversion.
//
// Conversion only changes fields, it never adds, removes, or reorders
// vulnerabilities or their ratings, so they can be matched up by index.
func restoreScores(original *cyclonedx.BOM, converted *cyclonedx.BOM) {
	if converted.Vulnerabilities == nil {
		return
	}

	originalVulns := *original.Vulnerabilities

	for i, vuln := range *converted.Vulnerabilities {
		if vuln.Ratings == nil {
			continue
		}

		originalRatings := *originalVulns[i].Ratings

		for j, rating := range *vuln.Ratings {
			// only restore scores that were lost, so we don't override any
			// changes that were made intentionally as part of the conversion
			if rating.Score == nil && originalRatings[j].Score != nil {
				score := *originalRatings[j].Score
				(*vuln.Ratings)[j].Score = &score
			}
		}
	}
}
