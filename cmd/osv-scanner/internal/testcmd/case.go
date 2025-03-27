package testcmd

import "github.com/google/osv-scanner/v2/internal/testutility"

type Case struct {
	Name string
	Args []string
	Exit int

	// ReplaceRules are only used for JSON output
	ReplaceRules []testutility.JSONReplaceRule
}

func (c Case) isOutputtingJSON() bool {
	for i, arg := range c.Args {
		if arg == "--format=json" {
			return true
		}

		if arg == "--format" && i < len(c.Args) && c.Args[i+1] == "json" {
			return true
		}
	}

	return false
}
