// Package cachedregexp provides a cached version of regexp.MustCompile and regexp.Compile.
package cachedregexp

import (
	"regexp"
	"sync"
)

var cache sync.Map

// Regexp is an alias for regexp.Regexp, allowing packages to use this type without importing regexp directly.
type Regexp = regexp.Regexp

func MustCompile(exp string) *regexp.Regexp {
	compiled, ok := cache.Load(exp)
	if !ok {
		compiled, _ = cache.LoadOrStore(exp, regexp.MustCompile(exp))
	}

	return compiled.(*regexp.Regexp)
}

// Compile returns a compiled regexp or an error if the pattern is invalid.
// Results are cached for performance.
func Compile(exp string) (*regexp.Regexp, error) {
	compiled, ok := cache.Load(exp)
	if ok {
		return compiled.(*regexp.Regexp), nil
	}

	r, err := regexp.Compile(exp)
	if err != nil {
		return nil, err
	}

	cache.LoadOrStore(exp, r)

	return r, nil
}
