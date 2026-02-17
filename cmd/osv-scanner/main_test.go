// main cannot be accessed directly, so cannot use main_test
package main

import (
	"os"
	"runtime"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
)

//nolint:paralleltest
func Test_run(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getenv("GITHUB_RUN_ATTEMPT") == "1" {
		t.Fail()
	}

	tests := []testcmd.Case{
		{
			Name: "",
			Args: []string{""},
			Exit: 127,
		},
		{
			Name: "",
			Args: []string{"--help"},
			Exit: 127,
		},
		{
			Name: "version",
			Args: []string{"", "--version"},
			Exit: 0,
		},
	}

	// No parallel because --version output is not thread safe.
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}

func Test_run_SubCommands(t *testing.T) {
	t.Parallel()

	client := testcmd.InsertCassette(t)

	tests := []testcmd.Case{
		// without subcommands
		{
			Name: "with no subcommand",
			Args: []string{"", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		// with scan subcommand
		{
			Name: "with scan subcommand",
			Args: []string{"", "scan", "./testdata/locks-many/composer.lock"},
			Exit: 0,
		},
		// scan with a flag
		{
			Name: "scan with a flag",
			Args: []string{"", "scan", "--recursive", "./testdata/locks-one-with-nested"},
			Exit: 0,
		},
		// TODO: add tests for other future subcommands
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			tt.HTTPClient = testcmd.WithTestNameHeader(t, *client)

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}
