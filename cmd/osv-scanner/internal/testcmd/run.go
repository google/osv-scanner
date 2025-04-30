package testcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/urfave/cli/v2"
)

// CommandsUnderTest should be set in TestMain by every cmd package test
var CommandsUnderTest []cmd.CommandBuilder

// fetchCommandsToTest returns the commands that should be tested, ensuring that
// the default "scan" command is included to avoid a panic
func fetchCommandsToTest() []cmd.CommandBuilder {
	for _, builder := range CommandsUnderTest {
		command := builder(nil, nil)

		if command.Name == "scan" {
			return CommandsUnderTest
		}
	}

	return append(CommandsUnderTest, func(_, _ io.Writer) *cli.Command {
		return &cli.Command{
			Name: "scan",
			Action: func(_ *cli.Context) error {
				return errors.New("<this test is unexpectedly calling the default scan command>")
			},
		}
	})
}

func run(t *testing.T, tc Case) (string, string) {
	t.Helper()

	stdout := newMuffledWriter()
	stderr := newMuffledWriter()

	ec := cmd.Run(tc.Args, stdout, stderr, fetchCommandsToTest())

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
