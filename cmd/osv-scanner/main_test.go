// main cannot be accessed directly, so cannot use main_test
package main

import (
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
)

//nolint:paralleltest
func Test_run(t *testing.T) {
	tests := []testcmd.Case{
		{
			Name: "",
			Args: []string{""},
			Exit: 0,
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

	tests := []testcmd.Case{
		// without subcommands
		{
			Name: "with no subcommand",
			Args: []string{"", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// with scan subcommand
		{
			Name: "with scan subcommand",
			Args: []string{"", "scan", "./fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		// scan with a flag
		{
			Name: "scan with a flag",
			Args: []string{"", "scan", "--recursive", "./fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		// TODO: add tests for other future subcommands
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			testcmd.RunAndMatchSnapshots(t, tt)
		})
	}
}
