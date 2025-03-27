package testcmd

type Case struct {
	Name string
	Args []string
	Exit int

	// ReplaceRules are only used for JSON output
	ReplaceRules []JSONReplaceRule
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
