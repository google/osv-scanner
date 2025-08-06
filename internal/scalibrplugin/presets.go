package scalibrplugin

import (
	"maps"

	detectors "github.com/google/osv-scalibr/detector/list"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargotoml"
	extractors "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

var detectorPresets = map[string]detectors.InitMap{
	"cis":         detectors.CIS,
	"govulncheck": detectors.Govulncheck,
	"untested":    detectors.Untested,
	"weakcreds":   detectors.Weakcredentials,
}

var ExtractorPresets = map[string]extractors.InitMap{
	"sbom": extractors.SBOM,
	"lockfile": concat(
		without(extractors.SourceCode, []string{
			pomxml.Name, pomxmlnet.Name,
			requirements.Name, requirementsnet.Name,
			secrets.Name, cargotoml.Name,
		}),
		extractors.InitMap{
			pomxmlenhanceable.Name:      {pomxmlenhanceable.New},
			requirementsenhancable.Name: {requirementsenhancable.New},
		},
	),
	"directory": {
		gitrepo.Name:  {gitrepo.New},
		vendored.Name: {vendored.New},
	},
	"artifact": concat(
		without(extractors.Artifact, []string{secrets.Name, packagejson.Name}),
		extractors.InitMap{
			nodemodules.Name: {nodemodules.New},
		},
	),
}

func without(initMap extractors.InitMap, omit []string) extractors.InitMap {
	result := extractors.InitMap{}

	maps.Copy(result, initMap)

	for _, name := range omit {
		delete(result, name)
	}

	return result
}

func concat(initMaps ...extractors.InitMap) extractors.InitMap {
	result := extractors.InitMap{}
	for _, m := range initMaps {
		maps.Copy(result, m)
	}

	return result
}
