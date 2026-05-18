package fix_test

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/testutility"
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

	testutility.SkipIfShort(t)

	tests := []testcmd.Case{
		{
			Name: "no_args_provided",
			Args: []string{"", "fix"},
			Exit: 127,
		},
		{
			Name: "fix_non-interactive_in-place_package-lock.json",
			Args: []string{"", "fix", "--strategy=in-place", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix_non_interactive_in_place_package_lock_json_with_native_data_source",
			Args: []string{"", "fix", "--strategy=in-place", "--data-source", "native", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix_non-interactive_relax_package.json",
			Args: []string{"", "fix", "--strategy=relax", "-M", "./testdata/relax-npm/package.json"},
			Exit: 0,
		},
		{
			Name: "fix_non-interactive_override_pom.xml",
			Args: []string{"", "fix", "--strategy=override", "-M", "./testdata/override-maven/pom.xml"},
			Exit: 0,
		},
		{
			Name: "fix_non_interactive_override_pom_xml_with_native_data_source",
			Args: []string{"", "fix", "--strategy=override", "--data-source", "native", "-M", "./testdata/override-maven/pom.xml"},
			Exit: 0,
		},
		{
			Name: "fix_non-interactive_json_in-place_package-lock.json",
			Args: []string{"", "fix", "--strategy=in-place", "--format=json", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix_non-interactive_json_relax_package.json",
			Args: []string{"", "fix", "--strategy=relax", "--format=json", "-M", "./testdata/relax-npm/package.json"},
			Exit: 0,
		},
		{
			Name: "fix_non-interactive_json_override_pom.xml",
			Args: []string{"", "fix", "--strategy=override", "--format=json", "-M", "./testdata/override-maven/pom.xml"},
			Exit: 0,
		},
		{
			Name: "errors_with_invalid_data_source",
			Args: []string{"", "fix", "--data-source=github"},
			Exit: 127,
		},
		{
			Name: "errors_with_unsupported_format",
			Args: []string{"", "fix", "--format=yaml"},
			Exit: 127,
		},
		{
			Name: "errors_with_unsupported_strategy",
			Args: []string{"", "fix", "--strategy=force"},
			Exit: 127,
		},
		{
			Name: "errors_when_in_place_used_without_lockfile",
			Args: []string{"", "fix", "--strategy=in-place", "-M", "./testdata/relax-npm/package.json"},
			Exit: 127,
		},
		{
			Name: "errors_when_relock_used_without_manifest",
			Args: []string{"", "fix", "--strategy=relock", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "errors_when_relax_used_without_manifest",
			Args: []string{"", "fix", "--strategy=relax", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 127,
		},
		{
			Name: "errors_when_override_used_without_manifest",
			Args: []string{"", "fix", "--strategy=override", "-L", "./testdata/in-place-npm/package-lock.json"},
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

func TestCommand_OfflineDatabase(t *testing.T) {
	t.Parallel()

	testutility.SkipIfShort(t)

	tests := []testcmd.Case{
		{
			Name: "fix_non_interactive_in_place_package_lock_json_with_offline_vulns",
			Args: []string{"", "fix", "--strategy=in-place", "--offline-vulnerabilities", "--download-offline-databases", "-L", "./testdata/in-place-npm/package-lock.json"},
			Exit: 0,
		},
		{
			Name: "fix_non_interactive_relax_package_json_with_offline_vulns",
			Args: []string{"", "fix", "--strategy=relax", "--offline-vulnerabilities", "--download-offline-databases", "-M", "./testdata/relax-npm/package.json"},
			Exit: 0,
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
