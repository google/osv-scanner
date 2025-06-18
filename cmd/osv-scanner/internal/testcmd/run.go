package testcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/urfave/cli/v3"
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
			Action: func(_ context.Context, _ *cli.Command) error {
				return errors.New("<this test is unexpectedly calling the default scan command>")
			},
		}
	})
}

func run(t *testing.T, tc Case) (string, string) {
	t.Helper()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	ec := cmd.Run(tc.Args, stdout, stderr, fetchCommandsToTest())

	if ec != tc.Exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.Exit)
	}

	return stdout.String(), stderr.String()
}

func RunAndMatchSnapshots(t *testing.T, tc Case) {
	t.Helper()

	stdout, stderr := run(t, tc)

	stdout = normalizeDirScanOrder(t, stdout)
	stderr = normalizeDirScanOrder(t, stderr)

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

// Sorts the output between directory scan markers to allow for consistent test results when doing unsorted dir walks
func normalizeDirScanOrder(t *testing.T, input string) string {
	t.Helper()

	inputLines := strings.Split(input, "\n")

	var completeOutput = make([]string, 0, len(inputLines))
	var dirScanHolder []string
	printingDirScanLogs := false

	for _, line := range inputLines {
		if strings.Contains(line, testlogger.BeginDirectoryScan) {
			if printingDirScanLogs {
				t.Fatalf("directory scan began twice before finishing?")
			}
			printingDirScanLogs = true

			continue
		}

		if strings.Contains(line, testlogger.EndDirectoryScan) {
			if !printingDirScanLogs {
				t.Fatalf("directory scan ended before starting?")
			}

			printingDirScanLogs = false
			sort.Strings(dirScanHolder)
			completeOutput = append(completeOutput, dirScanHolder...)
			dirScanHolder = nil

			continue
		}

		if printingDirScanLogs {
			dirScanHolder = append(dirScanHolder, line)

			continue
		}

		completeOutput = append(completeOutput, line)
	}

	return strings.Join(completeOutput, "\n")
}
