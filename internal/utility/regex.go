package utility

import (
	"regexp"
	"sync"
)

var compiledRegexCache sync.Map

func CachedRegexMustCompile(exp string) *regexp.Regexp {
	compiled, ok := compiledRegexCache.Load(exp)
	if !ok {
		compiled, _ = compiledRegexCache.LoadOrStore(exp, regexp.MustCompile(exp))
	}

	return compiled.(*regexp.Regexp)
}
