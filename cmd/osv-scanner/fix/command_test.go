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

	tests := []testcmd.Case{
		{
			Name: "no_args_provided",
			Args: []string{"", "fix"},
			Exit: 127,
		},
		{
			Name: "fix non-interactive in-place package-lock.json",
			Args: []string{"", "fix", "--strategy=in-place", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix_non_interactive_in_place_package_lock_json_with_native_data_source",
			Args: []string{"", "fix", "--strategy=in-place", "--data-source", "native", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix non-interactive relax package.json",
			Args: []string{"", "fix", "--strategy=relax", "-M", "./testdata/relax-npm/package.json"},
			Exit: 0,
		},
		{
			Name: "fix non-interactive override pom.xml",
			Args: []string{"", "fix", "--strategy=override", "-M", "./testdata/override-maven/pom.xml"},
			Exit: 0,
		},
		{
			Name: "fix_non_interactive_override_pom_xml_with_native_data_source",
			Args: []string{"", "fix", "--strategy=override", "--data-source", "native", "-M", "./testdata/override-maven/pom.xml"},
			Exit: 0,
		},
		{
			Name: "fix non-interactive json in-place package-lock.json",
			Args: []string{"", "fix", "--strategy=in-place", "--format=json", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix non-interactive json relax package.json",
			Args: []string{"", "fix", "--strategy=relax", "--format=json", "-M", "./testdata/relax-npm/package.json"},
			Exit: 0,
		},
		{
			Name: "fix non-interactive json override pom.xml",
			Args: []string{"", "fix", "--strategy=override", "--format=json", "-M", "./testdata/override-maven/pom.xml"},
			Exit: 0,
		},
		{
			Name: "errors_with_invalid_data_source",
			Args: []string{"", "fix", "--data-source=github"},
			Exit: 127,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// fix action overwrites files, copy them to a temporary directory
			testDir := testutility.CreateTestDir(t)

			lockfile := testcmd.CopyFileFlagTo(t, tt, "-L", testDir)
			manifest := testcmd.CopyFileFlagTo(t, tt, "-M", testDir)

			testcmd.RunAndMatchSnapshots(t, tt)

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
