package upgrade_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/remediation/upgrade"
)

func configSetExpect(t *testing.T, config upgrade.Config, pkg string, level upgrade.Level, want bool) {
	t.Helper()
	got := config.Set(pkg, level)
	if got != want {
		t.Errorf("Set(%v, %v) got %v, want %v", pkg, level, got, want)
	}
}

func configSetDefaultExpect(t *testing.T, config upgrade.Config, level upgrade.Level, want bool) {
	t.Helper()
	got := config.SetDefault(level)
	if got != want {
		t.Errorf("SetDefault(%v) got %v, want %v", level, got, want)
	}
}

func configGetExpect(t *testing.T, config upgrade.Config, pkg string, want upgrade.Level) {
	t.Helper()
	if got := config.Get(pkg); got != want {
		t.Errorf("Get(%v) got %v, want %v", pkg, got, want)
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()
	config := upgrade.NewConfig()

	// Default everything to allow major
	configGetExpect(t, config, "foo", upgrade.Major)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set specific package
	configSetExpect(t, config, "foo", upgrade.Minor, false)
	configGetExpect(t, config, "foo", upgrade.Minor)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set package again
	configSetExpect(t, config, "foo", upgrade.None, true)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set default
	configSetDefaultExpect(t, config, upgrade.Patch, false)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Patch)

	// Set default again
	configSetDefaultExpect(t, config, upgrade.Major, true)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Major)

	// Set other package
	configSetExpect(t, config, "bar", upgrade.Minor, false)
	configGetExpect(t, config, "foo", upgrade.None)
	configGetExpect(t, config, "bar", upgrade.Minor)
	configGetExpect(t, config, "baz", upgrade.Major)
}
