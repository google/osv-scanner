// Package testcmd provides test utilities for osv-scanner commands.
package testcmd

import (
	"net/http"
	"strings"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

type Case struct {
	Name string
	Args []string
	Skip string
	Exit int

	// ReplaceRules are only used for JSON output
	ReplaceRules []testutility.JSONReplaceRule

	HTTPClient      *http.Client
	ClientFactories scalibrconfig.ClientFactories
}

func (tc Case) findFirstValueOfFlag(flag string) string {
	return findFirstValueOfFlag(tc.Args, flag)
}

// findFirstValueOfFlag returns the value of the first instance of the given flag
func findFirstValueOfFlag(args []string, flag string) string {
	for i, arg := range args {
		if value, ok := strings.CutPrefix(arg, flag+"="); ok {
			return value
		}

		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}

	return ""
}
