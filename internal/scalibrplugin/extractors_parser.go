// Package scalibrplugin provides functions related to configuring scalibr plugins
package scalibrplugin

import (
	"maps"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsnet"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets"
	"github.com/google/osv-scanner/v2/internal/builders"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

var ExtractorPresets = map[string]list.InitMap{
	"sbom": list.SBOM,
	"lockfile": concat(
		without(list.SourceCode, []string{
			pomxml.Name, pomxmlnet.Name,
			requirements.Name, requirementsnet.Name,
			secrets.Name,
		}),
		list.InitMap{
			pomxmlenhanceable.Name:      {pomxmlenhanceable.New},
			requirementsenhancable.Name: {requirementsenhancable.New},
		},
	),
	"directory": {
		gitrepo.Name:  {gitrepo.New},
		vendored.Name: {vendored.New},
	},
	"artifact": concat(
		without(list.Artifact, []string{secrets.Name, packagejson.Name}),
		list.InitMap{
			nodemodules.Name: {nodemodules.New},
		},
	),
}

func without(initMap list.InitMap, omit []string) list.InitMap {
	result := list.InitMap{}

	maps.Copy(result, initMap)

	for _, name := range omit {
		delete(result, name)
	}

	return result
}

func concat(initMaps ...list.InitMap) list.InitMap {
	result := list.InitMap{}
	for _, m := range initMaps {
		maps.Copy(result, m)
	}

	return result
}

func ResolveEnabledExtractors(enabledExtractors []string, disabledExtractors []string) []filesystem.Extractor {
	extractors := make(map[string]bool)

	for i, exts := range [][]string{enabledExtractors, disabledExtractors} {
		enabled := i == 0

		for _, extractorOrPreset := range exts {
			if names, ok := ExtractorPresets[extractorOrPreset]; ok {
				for name := range names {
					extractors[name] = enabled
				}

				continue
			}

			extractors[extractorOrPreset] = enabled
		}
	}

	asSlice := make([]string, 0, len(extractors))

	for name, value := range extractors {
		if name != "" && value {
			asSlice = append(asSlice, name)
		}
	}

	return builders.BuildExtractors(asSlice)
}
