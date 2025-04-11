package testcmd

import (
	"bytes"
	"encoding/json"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func run(t *testing.T, tc Case) (string, string) {
	t.Helper()

	stdout := newMuffledWriter()
	stderr := newMuffledWriter()
	handler, ok := slog.Default().Handler().(*testlogger.TestLogger)
	if !ok {
		t.Fatalf("Test failed to initialize default logger with TestLogger")
	}

	handler.AddInstance(stdout, stderr)
	ec := cmd.Run(tc.Args, stdout, stderr)
	// Deleting is very important, as when this test ends the same memory address
	// could (and is) used for new test calls.
	handler.Delete()

	if ec != tc.Exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.Exit)
	}

	return stdout.String(), stderr.String()
}

func RunAndMatchSnapshots(t *testing.T, tc Case) {
	t.Helper()

	stdout, stderr := run(t, tc)

	if tc.isOutputtingJSON() {
		stdout = normalizeJSON(t, stdout, tc.ReplaceRules...)
	}

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().WithWindowsReplacements(map[string]string{
		"CreateFile": "stat",
	}).MatchText(t, stderr)
}

// normalizeJSON runs the given JSONReplaceRules on the given JSON input and returns the normalized JSON string
func normalizeJSON(t *testing.T, jsonInput string, jsonReplaceRules ...JSONReplaceRule) string {
	t.Helper()

	for _, rule := range jsonReplaceRules {
		jsonInput = replaceJSONInput(t, jsonInput, rule.Path, rule.ReplaceFunc)
	}

	jsonFormatted := bytes.Buffer{}
	err := json.Indent(&jsonFormatted, []byte(jsonInput), "", "  ")

	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	return jsonFormatted.String()
}
