package fix_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/remediation/upgrade"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/urfave/cli/v3"
)

func matchFile(t *testing.T, file string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}
	testutility.NewSnapshot().WithCRLFReplacement().MatchText(t, string(b))
}

func TestCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		exit     int
		manifest string
		lockfile string
	}{
		{
			name:     "fix non-interactive in-place package-lock.json",
			args:     []string{"", "fix", "--strategy=in-place"},
			exit:     0,
			lockfile: "./fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive relax package.json",
			args:     []string{"", "fix", "--strategy=relax"},
			exit:     0,
			manifest: "./fixtures/relax-npm/package.json",
		},
		{
			name:     "fix non-interactive override pom.xml",
			args:     []string{"", "fix", "--strategy=override"},
			exit:     0,
			manifest: "./fixtures/override-maven/pom.xml",
		},
		{
			name:     "fix non-interactive json in-place package-lock.json",
			args:     []string{"", "fix", "--strategy=in-place", "--format=json"},
			exit:     0,
			lockfile: "./fixtures/in-place-npm/package-lock.json",
		},
		{
			name:     "fix non-interactive json relax package.json",
			args:     []string{"", "fix", "--strategy=relax", "--format=json"},
			exit:     0,
			manifest: "./fixtures/relax-npm/package.json",
		},
		{
			name:     "fix non-interactive json override pom.xml",
			args:     []string{"", "fix", "--strategy=override", "--format=json"},
			exit:     0,
			manifest: "./fixtures/override-maven/pom.xml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tc := testcmd.Case{
				Name: tt.name,
				Args: slices.Clone(tt.args),
				Exit: tt.exit,
			}

			// fix action overwrites files, copy them to a temporary directory
			testDir := testutility.CreateTestDir(t)

			var lockfile, manifest string
			if tt.lockfile != "" {
				lockfile = testcmd.CopyFileTo(t, tt.lockfile, testDir)
				tc.Args = append(tc.Args, "-L", lockfile)
			}
			if tt.manifest != "" {
				manifest = testcmd.CopyFileTo(t, tt.manifest, testDir)
				tc.Args = append(tc.Args, "-M", manifest)
			}

			testcmd.RunAndMatchSnapshots(t, tc)

			if lockfile != "" {
				matchFile(t, lockfile)
			}
			if manifest != "" {
				matchFile(t, manifest)
			}
		})
	}
}

func parseFlags(t *testing.T, flags []string, arguments []string) (*cli.Command, error) {
	// This is a bit hacky: make a mock App with only the flags we care about.
	// Then use app.RunAndMatchSnapshots() to parse the flags into the cli.Context, which is returned.
	t.Helper()
	appFlags := make([]cli.Flag, 0, len(flags))
	for _, f := range fix.Command(nil, nil).Flags {
		if slices.ContainsFunc(f.Names(), func(s string) bool { return slices.Contains(flags, s) }) {
			appFlags = append(appFlags, f)
		}
	}
	var parsedCmd *cli.Command
	app := cli.Command{
		Flags: appFlags,
		Action: func(_ context.Context, cmd *cli.Command) error {
			t.Helper()
			parsedCmd = cmd

			return nil
		},
	}
	err := app.Run(t.Context(), append([]string{""}, arguments...))

	return parsedCmd, err
}

func Test_parseUpgradeConfig(t *testing.T) {
	t.Parallel()

	flags := []string{"upgrade-config"}

	tests := []struct {
		name string
		args []string
		want map[string]upgrade.Level
	}{
		{
			name: "default behaviour",
			args: []string{},
			want: map[string]upgrade.Level{
				"foo": upgrade.Major,
				"bar": upgrade.Major,
			},
		},
		{
			name: "general level config",
			args: []string{"--upgrade-config=minor"},
			want: map[string]upgrade.Level{
				"foo": upgrade.Minor,
				"bar": upgrade.Minor,
			},
		},
		{
			name: "all levels",
			args: []string{
				"--upgrade-config", "major:major",
				"--upgrade-config", "minor:minor",
				"--upgrade-config", "patch:patch",
				"--upgrade-config", "none:none",
			},
			want: map[string]upgrade.Level{
				"major": upgrade.Major,
				"minor": upgrade.Minor,
				"patch": upgrade.Patch,
				"none":  upgrade.None,
				"other": upgrade.Major,
			},
		},
		{
			name: "package takes precedence over general",
			args: []string{
				"--upgrade-config", "pkg1:minor",
				"--upgrade-config", "none",
				"--upgrade-config", "pkg2:major",
			},
			want: map[string]upgrade.Level{
				"pkg1": upgrade.Minor,
				"pkg2": upgrade.Major,
				"pkg3": upgrade.None,
			},
		},
		{
			name: "package names with colons",
			args: []string{
				"--upgrade-config=none:patch:minor:major",
				"--upgrade-config=none:patch:minor",
				"--upgrade-config=none:patch",
				"--upgrade-config=none",
			},
			want: map[string]upgrade.Level{
				"none:patch:minor": upgrade.Major,
				"none:patch":       upgrade.Minor,
				"none":             upgrade.Patch,
				"other":            upgrade.None,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, err := parseFlags(t, flags, tt.args)
			if err != nil {
				t.Fatalf("error parsing flags: %v", err)
			}
			config := upgrade.ParseUpgradeConfig(cmd.StringSlice("upgrade-config"))
			for pkg, want := range tt.want {
				if got := config.Get(pkg); got != want {
					t.Errorf("Config.Get(%s) got = %v, want %v", pkg, got, want)
				}
			}
		})
	}
}
