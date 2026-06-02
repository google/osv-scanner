package gitlab

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	// VersionMajor is the major number of the current version
	VersionMajor = 15
	// VersionMinor is the minor number of the current version
	VersionMinor = 2
	// VersionPatch is the patch number of the current version
	VersionPatch = 4
	// VersionPreRelease is the optional suffix for pre-releases
	VersionPreRelease = ""
)

// CurrentVersion returns the current version of the report syntax.
func CurrentVersion() Version {
	return Version{VersionMajor, VersionMinor, VersionPatch, VersionPreRelease}
}

// Version represents the version of the report syntax.
// It matches a release of the Security Report Schemas, and is used for JSON schema validation.
// See https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases
type Version struct {
	Major      uint
	Minor      uint
	Patch      uint
	PreRelease string
}

// MarshalJSON encodes a version to JSON.
func (v Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// UnmarshalJSON decodes a version.
func (v *Version) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	// set to default version if empty string
	if s == "" {
		v.Major = VersionMajor
		v.Minor = VersionMinor
		v.Patch = VersionPatch
		return nil
	}

	// parse pre-release
	parts := strings.SplitN(s, "-", 2)
	if len(parts) > 1 {
		v.PreRelease = parts[1]
	}

	// parse segments
	parts = strings.SplitN(parts[0], ".", 3)
	for i := range parts {
		un, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil {
			return err
		}

		n := uint(un)
		switch i {
		case 0:
			v.Major = n
		case 1:
			v.Minor = n
		case 2:
			v.Patch = n
		}
	}

	return nil
}

// String turns the version into a "MAJOR.MINOR.PATCH" string, with an optional "-PRERELEASE" suffix.
func (v Version) String() string {
	var pre string
	if v.PreRelease != "" {
		pre = fmt.Sprintf("-%s", v.PreRelease)
	}
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, pre)
}
