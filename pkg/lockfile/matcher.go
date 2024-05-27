package lockfile

type Matcher interface {
	GetSourceFile(lockfile DepFile) (DepFile, error)
	Match(sourceFile DepFile, packages []PackageDetails) error
}

func matchWithFile(lockfile DepFile, packages []PackageDetails, matcher Matcher) error {
	sourceFile, err := matcher.GetSourceFile(lockfile)

	if err != nil {
		return err
	}

	return matcher.Match(sourceFile, packages)
}
