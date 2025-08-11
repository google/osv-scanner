package testcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
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

func RunAndNormalize(t *testing.T, tc Case) (string, string) {
	t.Helper()

	stdout, stderr := run(t, tc)

	stdout = normalizeDirScanOrder(t, stdout)
	stderr = normalizeDirScanOrder(t, stderr)

	if len(tc.ReplaceRules) > 0 {
		stdout = normalizeJSON(t, stdout, tc.ReplaceRules...)
	}

	stdout = normalizeUUID(t, stdout)

	return stdout, stderr
}

func RunAndMatchSnapshots(t *testing.T, tc Case) {
	t.Helper()

	stdout, stderr := RunAndNormalize(t, tc)

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

// normalizeUUID normalizes each unique instance of uuid string into it's own placeholder, so relations are preserved.
func normalizeUUID(t *testing.T, input string) string {
	t.Helper()

	uuidV4Regexp := cachedregexp.MustCompile(
		"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89ABab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}")

	uuidMapping := map[string]int{}
	allUUIDs := uuidV4Regexp.FindAllString(input, -1)

	for _, id := range allUUIDs {
		if _, ok := uuidMapping[id]; ok {
			continue
		}

		// Create a incrementing uuid mapping for each unique uuid we encounter
		uuidMapping[id] = len(uuidMapping)
	}

	replacerRules := make([]string, 0, len(uuidMapping)*2)
	for s, i := range uuidMapping {
		replacerRules = append(replacerRules, s, fmt.Sprintf("uuid-placeholder-%d", i))
	}

	return strings.NewReplacer(replacerRules...).Replace(input)
}
