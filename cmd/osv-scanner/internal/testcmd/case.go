package testcmd

import "github.com/google/osv-scanner/v2/internal/testutility"

type Case struct {
	Name string
	Args []string
	Exit int

	// ReplaceRules are only used for JSON output
	ReplaceRules []testutility.JSONReplaceRule
}
