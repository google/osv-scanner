package cmd

import (
	"bytes"
	"log/slog"
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/urfave/cli/v3"
)

func Test_insertDefaultCommand(t *testing.T) {
	t.Parallel()

	commands := []*cli.Command{
		{Name: "default"},
		{Name: "helpers.go"},
		{Name: "scan"},
	}
	defaultCommand := "default"

	tests := []struct {
		originalArgs []string
		wantArgs     []string
	}{
		// test when default command is specified
		{
			originalArgs: []string{"", "default", "file"},
			wantArgs:     []string{"", "default", "source", "file"},
		},
		// test when command is not specified
		{
			originalArgs: []string{"", "file"},
			wantArgs:     []string{"", "default", "source", "file"},
		},
		// test when command is also a filename
		{
			originalArgs: []string{"", "helpers.go"},
			wantArgs:     []string{"", "helpers.go"},
		},
		// test when subcommand is also a filename
		{
			originalArgs: []string{"", "default", "image"},
			wantArgs:     []string{"", "default", "image"},
		},
		// test when command is not valid
		{
			originalArgs: []string{"", "invalid"},
			wantArgs:     []string{"", "default", "source", "invalid"},
		},
		// test when command is a built-in option
		{
			originalArgs: []string{"", "--version"},
			wantArgs:     []string{"", "--version"},
		},
		{
			originalArgs: []string{"", "-h"},
			wantArgs:     []string{"", "-h"},
		},
		{
			originalArgs: []string{"", "help"},
			wantArgs:     []string{"", "help"},
		},
	}

	for _, tt := range tests {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}

		logger := cmdlogger.New(stdout, stderr)

		slog.SetDefault(slog.New(logger))

		argsActual := insertDefaultCommand(tt.originalArgs, commands, defaultCommand, stderr)
		if !reflect.DeepEqual(argsActual, tt.wantArgs) {
			t.Errorf("Test Failed. Details:\n"+
				"Args (Got):  %s\n"+
				"Args (Want): %s\n", argsActual, tt.wantArgs)
		}
		testutility.NewSnapshot().MatchText(t, stdout.String())
		testutility.NewSnapshot().MatchText(t, stderr.String())
	}
}
