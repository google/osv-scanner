package terminal

import "testing"

func TestEscapeGitHubActionsCommandChars(t *testing.T) {
	t.Parallel()

	got := EscapeGitHubActionsCommandChars("dir\r::warning::pwn\nnext")
	want := "dir%0D::warning::pwn%0Anext"

	if got != want {
		t.Fatalf("EscapeGitHubActionsCommandChars() = %q, want %q", got, want)
	}
}
