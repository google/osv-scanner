// Package builders provides functions to convert extractors from name.
package builders

import (
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

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
