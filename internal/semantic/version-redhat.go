package semantic

import "strings"

type RedHatVersion struct {
	epoch   string
	version string
	release string
	arch    string
}

func (v RedHatVersion) CompareStr(str string) int {
	panic("implement me")
}

// ParseRedHatVersion parses a Red Hat version into a RedHatVersion struct.
//
// A Red Hat version contains the following components:
// - name (of the package), represented as "n"
// - epoch, represented as "e"
// - version, represented as "v"
// - release, represented as "r"
// - architecture, represented as "a"
//
// When all components are present, the version is represented as "n-e:v-r.a",
// though only the version is actually required.
func parseRedHatVersion(str string) RedHatVersion {
	bf, af, hasColon := strings.Cut(str, ":")

	if !hasColon {
		af, bf = bf, af
	}

	// (note, we don't actually use the name)
	name, epoch, hasName := strings.Cut(bf, "-")

	if !hasName {
		epoch, name = name, epoch
	}

	middle, arch, _ := strings.Cut(af, ".")
	version, release, _ := strings.Cut(middle, "-")

	return RedHatVersion{
		epoch:   epoch,
		version: version,
		release: release,
		arch:    arch,
	}
}

// - RPM package names are made up of five parts; the package name, epoch, version, release, and architecture (NEVRA)
// - The epoch is not always included; it is assumed to be zero (0) on any packages that lack it explicitly
// - The format for the whole string is n-e:v-r.a
//
// - parsing:
//   - If there is a : in the string, everything before it is the epoch. If not, the epoch is zero.
//   - If there is a - in the remaining string, everything before the first - is the version, and everything after it is the release. If there isn’t one, the release is considered null/nill/None/whatever.
