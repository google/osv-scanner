package builders

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/python/requirementsenhancable"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
)

func build(name string) []filesystem.Extractor {
	switch name {
	// Java
	case pomxmlenhanceable.Name:
		return []filesystem.Extractor{pomxmlenhanceable.New()}
	// Javascript
	case nodemodules.Name:
		return []filesystem.Extractor{nodemodules.Extractor{}}
	// Python
	case requirementsenhancable.Name:
		return []filesystem.Extractor{requirementsenhancable.New()}
	// Directories
	case vendored.Name:
		return []filesystem.Extractor{&vendored.Extractor{}}
	case gitrepo.Name:
		return []filesystem.Extractor{&gitrepo.Extractor{}}
	}

	extractors, err := list.ExtractorsFromName(name)

	if err != nil {
		cmdlogger.Errorf("%s", err)

		return nil
	}

	return extractors
}

func BuildExtractors(names []string) []filesystem.Extractor {
	extractors := make([]filesystem.Extractor, 0, len(names))

	for _, name := range names {
		extractors = append(extractors, build(name)...)
	}

	return extractors
}
