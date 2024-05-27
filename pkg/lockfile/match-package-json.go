package lockfile

type PackageJSONMatcher struct{}

func (m PackageJSONMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("package.json")
}

func (m PackageJSONMatcher) Match(_ DepFile, _ []PackageDetails) error {
	return nil
}

var _ Matcher = PackageJSONMatcher{}
