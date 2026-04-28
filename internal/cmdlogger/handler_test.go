package cmdlogger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestHandlerEscapesGitHubActionsCommandChars(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	handler := New(stdout, stderr)

	err := handler.Handle(context.Background(), slog.NewRecord(
		time.Time{},
		slog.LevelInfo,
		"Scanning dir safe\r::warning::pwn\nnext",
		0,
	))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	got := stdout.String()
	if strings.ContainsAny(got, "\r") {
		t.Fatalf("log output contains raw carriage return: %q", got)
	}

	want := "Scanning dir safe%0D::warning::pwn%0Anext\n"
	if got != want {
		t.Fatalf("log output = %q, want %q", got, want)
	}
}
