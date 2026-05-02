package output

import "strings"

// workflowCommandReplacer URL-encodes \r and \n so user-controlled strings
// (file paths, source names) cannot inject GitHub Actions workflow commands
// when written to stdout. The GHA runner treats both bytes as line boundaries
// when scanning for ::command::value sequences.
var workflowCommandReplacer = strings.NewReplacer("\r", "%0D", "\n", "%0A")

// SanitizeForWorkflowCommand returns s with carriage-return and newline bytes
// replaced by their URL-encoded forms (%0D, %0A) so that an attacker-controlled
// value cannot break out of its line and inject GitHub Actions workflow
// commands such as ::error::, ::warning::, ::add-mask::, or ::stop-commands::.
func SanitizeForWorkflowCommand(s string) string {
	return workflowCommandReplacer.Replace(s)
}
