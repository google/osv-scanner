package scan_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
)

func TestCommand_SubCommands(t *testing.T) {
	tests := []testcmd.Case{
		{
			Name: "with no subcommands, showing help",
			Args: []string{"", "scan", "--help"},
			Exit: 0,
		},
		{
			Name: "with no subcommands",
			Args: []string{"", "scan", "../fixtures/locks-many/composer.lock"},
			Exit: 0,
		},
		{
			Name: "with a flag",
			Args: []string{"", "scan", "--recursive", "../fixtures/locks-one-with-nested"},
			Exit: 0,
		},
		{
			Name: "with source subcommand",
			Args: []string{"", "scan", "source", "--help"},
			Exit: 0,
		},
		{
			Name: "with image subcommand",
			Args: []string{"", "scan", "image", "--help"},
			Exit: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			testcmd.Test(t, tt)
		})
	}
}
