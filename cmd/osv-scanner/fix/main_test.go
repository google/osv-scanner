package fix

import (
	"slices"
	"testing"

	"github.com/google/osv-scanner/internal/remediation/upgrade"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/urfave/cli/v2"
)

func parseFlags(t *testing.T, flags []string, arguments []string) (*cli.Context, error) {
	// This is a bit hacky: make a mock App with only the flags we care about.
	// Then use app.Run() to parse the flags into the cli.Context, which is returned.
	t.Helper()
	appFlags := make([]cli.Flag, 0, len(flags))
	for _, f := range Command(nil, nil, nil).Flags {
		if slices.ContainsFunc(f.Names(), func(s string) bool { return slices.Contains(flags, s) }) {
			appFlags = append(appFlags, f)
		}
	}
	var parsedContext *cli.Context
	app := cli.App{
		Flags: appFlags,
		Action: func(ctx *cli.Context) error {
			t.Helper()
			parsedContext = ctx

			return nil
		},
	}
	err := app.Run(append([]string{""}, arguments...))

	return parsedContext, err
}

func TestParseUpgradeConfig(t *testing.T) {
	t.Parallel()
	flags := []string{"upgrade-config", "disallow-major-upgrades", "disallow-package-upgrades"}

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
		{
			name: "deprecated flag",
			args: []string{
				"--disallow-major-upgrades",
				"--disallow-package-upgrades=pkg1,pkg2",
				"--upgrade-config=pkg3:patch",
			},
			want: map[string]upgrade.Level{
				"pkg1": upgrade.None,
				"pkg2": upgrade.None,
				"pkg3": upgrade.Patch,
				"pkg4": upgrade.Minor,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, err := parseFlags(t, flags, tt.args)
			if err != nil {
				t.Fatalf("error parsing flags: %v", err)
			}
			config := parseUpgradeConfig(ctx, &reporter.VoidReporter{})
			for pkg, want := range tt.want {
				if got := config.Get(pkg); got != want {
					t.Errorf("Config.Get(%s) got = %v, want %v", pkg, got, want)
				}
			}
		})
	}
}
