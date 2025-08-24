// Package testcmd provides utilities for testing osv-scanner CLI commands.
package testcmd

import (
	"net/http"
	"strings"
)

type Case struct {
	Name string
	Args []string
	Exit int

	// ReplaceRules are only used for JSON output
	ReplaceRules []JSONReplaceRule

	HTTPClient *http.Client
}

// findFirstValueOfFlag returns the value of the first instance of the given flag
// in the test case arguments, if it is present at all
func (c Case) findFirstValueOfFlag(f string) string {
	for i, arg := range c.Args {
		if after, ok := strings.CutPrefix(arg, f+"="); ok {
			return after
		}

		if arg == f && i < len(c.Args) {
			return c.Args[i+1]
		}
	}

	return ""
}
