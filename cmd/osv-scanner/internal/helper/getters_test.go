package helper

import (
	"context"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestGetCommonScannerActions_OfflineFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                      string
		args                      []string
		wantCompareOffline        bool
		wantPluginNetworkDisabled bool
		wantNoResolve             bool
	}{
		{
			name:                      "offline_vulnerabilities_only",
			args:                      []string{"osv-scanner", "--offline-vulnerabilities"},
			wantCompareOffline:        true,
			wantPluginNetworkDisabled: false,
		},
		{
			name:                      "offline_sets_composite_flags",
			args:                      []string{"osv-scanner", "--offline"},
			wantCompareOffline:        true,
			wantPluginNetworkDisabled: true,
			wantNoResolve:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var actionsCompareOffline bool
			var actionsPluginNetworkDisabled bool
			var noResolve bool

			cmd := &cli.Command{
				Flags: BuildCommonScanFlags(nil),
				Action: func(_ context.Context, cmd *cli.Command) error {
					actions := GetCommonScannerActions(cmd, nil)
					actionsCompareOffline = actions.CompareOffline
					actionsPluginNetworkDisabled = actions.PluginNetworkDisabled
					noResolve = cmd.Bool("no-resolve")

					return nil
				},
			}

			if err := cmd.Run(context.Background(), tt.args); err != nil {
				t.Fatalf("cmd.Run() error = %v", err)
			}

			if actionsCompareOffline != tt.wantCompareOffline {
				t.Errorf("actions.CompareOffline = %v, want %v", actionsCompareOffline, tt.wantCompareOffline)
			}
			if actionsPluginNetworkDisabled != tt.wantPluginNetworkDisabled {
				t.Errorf("actions.PluginNetworkDisabled = %v, want %v", actionsPluginNetworkDisabled, tt.wantPluginNetworkDisabled)
			}
			if noResolve != tt.wantNoResolve {
				t.Errorf("cmd.Bool(%q) = %v, want %v", "no-resolve", noResolve, tt.wantNoResolve)
			}
		})
	}
}
