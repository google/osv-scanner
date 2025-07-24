// Package semverlike provides functionality to parse and compare version strings
// that are similar to semantic versioning, but with more flexibility.
// It is currently used to parse go mod versions to determine if a patch version exists.
package semverlike

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
)

// Components are individual components of each semver segment.
type Components []*big.Int

func (components *Components) Fetch(n int) *big.Int {
	if len(*components) <= n {
		return big.NewInt(0)
	}

	return (*components)[n]
}

func (components *Components) Cmp(b Components) int {
	numberOfComponents := max(len(*components), len(b))

	for i := range numberOfComponents {
		diff := components.Fetch(i).Cmp(b.Fetch(i))

		if diff != 0 {
			return diff
		}
	}

	return 0
}

// Version is a version that is _like_ a version as defined by the
// Semantic Version specification, except with potentially unlimited numeric
// components and a leading "v"
type Version struct {
	LeadingV   bool
	Components Components
	Build      string
	Original   string
}

func (v *Version) fetchComponentsAndBuild(maxComponents int) (Components, string) {
	if len(v.Components) <= maxComponents {
		return v.Components, v.Build
	}

	comps := v.Components[:maxComponents]
	extra := v.Components[maxComponents:]

	build := v.Build

	for _, c := range extra {
		build += fmt.Sprintf(".%d", c)
	}

	return comps, build
}

func ParseSemverLikeVersion(line string, maxComponents int) Version {
	v := parseSemverLike(line)

	components, build := v.fetchComponentsAndBuild(maxComponents)

	return Version{
		LeadingV:   v.LeadingV,
		Components: components,
		Build:      build,
		Original:   v.Original,
	}
}

func parseSemverLike(line string) Version {
	var components []*big.Int
	originStr := line

	numberReg := cachedregexp.MustCompile(`\d`)

	currentCom := ""
	foundBuild := false

	leadingV := strings.HasPrefix(line, "v")
	line = strings.TrimPrefix(line, "v")

	for _, c := range line {
		if foundBuild {
			currentCom += string(c)

			continue
		}

		// this is part of a component version
		if numberReg.MatchString(string(c)) {
			currentCom += string(c)

			continue
		}

		// at this point, we:
		//   1. might be parsing a component (as foundBuild != true)
		//   2. we're not looking at a part of a component (as c != number)
		//
		// so c must be either:
		//   1. a component terminator (.), or
		//   2. the start of the build string
		//
		// either way, we will be terminating the current component being
		// parsed (if any), so let's do that first
		if currentCom != "" {
			v, _ := new(big.Int).SetString(currentCom, 10)

			components = append(components, v)
			currentCom = ""
		}

		// a component terminator means there might be another component
		// afterwards, so don't start parsing the build string just yet
		if c == '.' {
			continue
		}

		// anything else is part of the build string
		foundBuild = true
		currentCom = string(c)
	}

	// if we looped over everything without finding a build string,
	// then what we were currently parsing is actually a component
	if !foundBuild && currentCom != "" {
		v, _ := new(big.Int).SetString(currentCom, 10)

		components = append(components, v)
		currentCom = ""
	}

	return Version{
		LeadingV:   leadingV,
		Components: components,
		Build:      currentCom,
		Original:   originStr,
	}
}
