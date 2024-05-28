package lockfile

import "github.com/google/osv-scanner/pkg/models"

type PackageJSONMatcher struct{}

func (m PackageJSONMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("package.json")
}

func (m PackageJSONMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	for key := range packages {
		// TODO: temporal
		packages[key].BlockLocation = models.FilePosition{
			Line:     models.Position{Start: 1, End: 1},
			Column:   models.Position{Start: 1, End: 1},
			Filename: sourcefile.Path(),
		}
	}

	return nil
}

var _ Matcher = PackageJSONMatcher{}
