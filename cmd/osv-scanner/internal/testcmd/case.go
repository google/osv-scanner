// Package testcmd provides utilities for testing osv-scanner CLI commands.
package testcmd

import (
	"strings"
)

type Case struct {
	Name string
	Args []string
	Exit int

	// ReplaceRules are only used for JSON output
	ReplaceRules []JSONReplaceRule
}

// findFirstValueOfFlag returns the value of the first instance of the given flag
// in the test case arguments, if it is present at all
func (c Case) findFirstValueOfFlag(f string) string {
	for i, arg := range c.Args {
		if strings.HasPrefix(arg, f+"=") {
			return strings.TrimPrefix(arg, f+"=")
		}

		if arg == f && i < len(c.Args) {
			return c.Args[i+1]
		}
	}

	return ""
}
