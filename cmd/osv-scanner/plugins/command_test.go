package plugins_test

import (
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
)

func TestCommand_List(t *testing.T) {
	t.Parallel()

	stdout, stderr := testcmd.RunAndNormalize(t, testcmd.Case{
		Name: "list",
		Args: []string{"", "plugins", "list"},
		Exit: 0,
	})

	if stderr != "" {
		t.Fatalf("plugins list wrote to stderr: %q", stderr)
	}

	for _, want := range []string{
		"Available plugin presets:",
		"extractors: artifact, directory, lockfile, sbom",
		"detectors: cis, govulncheck, untested, weakcreds",
		"annotators: artifact",
		"enrichers: artifact, licenses, transitive, vulns",
		"Available exact plugin names:",
		"javascript/packagelockjson",
		"os/apk",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("plugins list output missing %q\noutput:\n%s", want, stdout)
		}
	}
}

func TestCommand_Help(t *testing.T) {
	t.Parallel()

	stdout, stderr := testcmd.RunAndNormalize(t, testcmd.Case{
		Name: "help",
		Args: []string{"", "plugins", "--help"},
		Exit: 127,
	})

	combined := stdout + "\n" + stderr
	for _, want := range []string{
		"osv-scanner plugins",
		"lists the available experimental plugin presets and exact plugin names",
		"list",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("plugins help output missing %q\noutput:\n%s", want, combined)
		}
	}
}
