package semantic

// AlpineVersion represents a version of an Alpine package.
//
// Currently, the APK version specification is as follows:
// *number{.number}...{letter}{\_suffix{number}}...{~hash}{-r#}*
//
// Each *number* component is a sequence of digits (0-9).
//
// The *letter* portion can follow only after end of all the numeric
// version components. The *letter* is a single lower case letter (a-z).
// This can follow one or more *\_suffix{number}* components. The list
// of valid suffixes (and their sorting order) is:
// *alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*
//
// This can be follows with an optional *{~hash}* to indicate a commit
// hash from where it was built. This can be any length string of
// lower case hexadecimal digits (0-9a-f).
//
// Finally, an optional package build component *-r{number}* can follow.
//
// Also see https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd#package-info-metadata
type AlpineVersion struct {
	//
}

func (v AlpineVersion) Compare(w AlpineVersion) int {
	return 0
}

func (v AlpineVersion) CompareStr(str string) int {
	return v.Compare(parseAlpineVersion(str))
}

func parseAlpineVersion(str string) AlpineVersion {
	return AlpineVersion{}
}
