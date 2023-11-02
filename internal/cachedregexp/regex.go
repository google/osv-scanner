package cachedregexp

import (
	"regexp"
	"sync"
)

var cache sync.Map

func MustCompile(exp string) *regexp.Regexp {
	compiled, ok := cache.Load(exp)
	if !ok {
		compiled, _ = cache.LoadOrStore(exp, regexp.MustCompile(exp))
	}

	return compiled.(*regexp.Regexp)
}

// Compile compiles a regular expression and caches it.
func Compile(exp string) (*regexp.Regexp, error) {
	compiled, ok := cache.Load(exp)
	if !ok {
		re, err := regexp.Compile(exp)
		if err != nil {
			return nil, err
		}
		compiled, _ = cache.LoadOrStore(exp, re)
	}

	return compiled.(*regexp.Regexp), nil
}
