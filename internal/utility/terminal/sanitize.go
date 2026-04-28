package terminal

import "strings"

var ghaCommandReplacer = strings.NewReplacer(
	"\r", "%0D",
	"\n", "%0A",
)

// EscapeGitHubActionsCommandChars escapes line terminators that GitHub Actions
// treats as workflow command boundaries.
func EscapeGitHubActionsCommandChars(s string) string {
	return ghaCommandReplacer.Replace(s)
}
