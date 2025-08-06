package scalibrplugin

import (
	"fmt"

	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

func BuildExtractor(name string) (plugin.Plugin, error) {
	switch name {
	// Java
	case pomxmlenhanceable.Name:
		return pomxmlenhanceable.New(), nil
	// Javascript
	case nodemodules.Name:
		return nodemodules.New(), nil
	// Python
	case requirementsenhancable.Name:
		return requirementsenhancable.New(), nil
	// Directories
	case vendored.Name:
		return vendored.New(), nil
	case gitrepo.Name:
		return gitrepo.New(), nil
	default:
		return nil, fmt.Errorf("not an exact name for a plugin: %q", name)
	}
}

func BuildExtractors(names []string) []plugin.Plugin {
	extractors := make([]plugin.Plugin, 0, len(names))

	for _, name := range names {
		switch name {
		// Java
		case pomxmlenhanceable.Name:
			extractors = append(extractors, pomxmlenhanceable.New())
		// Javascript
		case nodemodules.Name:
			extractors = append(extractors, nodemodules.New())
		// Python
		case requirementsenhancable.Name:
			extractors = append(extractors, requirementsenhancable.New())
		// Directories
		case vendored.Name:
			extractors = append(extractors, vendored.New())
		case gitrepo.Name:
			extractors = append(extractors, gitrepo.New())
		default:
			extras, err := list.ExtractorsFromName(name)

			if err != nil {
				cmdlogger.Errorf("%s", err)

				continue
			}

			for _, extra := range extras {
				extractors = append(extractors, extra)
			}
		}
	}

	return extractors
}
