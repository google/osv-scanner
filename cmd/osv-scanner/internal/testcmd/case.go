// Package testcmd provides utilities for testing osv-scanner CLI commands.
package testcmd

import (
	"net/http"
	"strings"

	"github.com/google/osv-scanner/v2/internal/grpcvcr"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

type Case struct {
	Name string
	Args []string
	Exit int

	// If Skip is not empty, the test will be skipped with the following reason.
	Skip string

	// ReplaceRules are only used for JSON output
	ReplaceRules []testutility.JSONReplaceRule

	// NoVCR disables automatic VCR recording/replaying for this test case.
	NoVCR bool

	HTTPClient   *http.Client
	GRPCRecorder *grpcvcr.Recorder
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
