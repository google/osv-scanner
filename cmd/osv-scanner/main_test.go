//nolint:testpackage // main cannot be accessed directly, so cannot use main_test
package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func dedent(t *testing.T, str string) string {
	t.Helper()

	// 0. replace all tabs with spaces
	str = strings.ReplaceAll(str, "\t", "  ")

	// 1. remove trailing whitespace
	re := regexp.MustCompile(`\r?\n([\t ]*)$`)
	str = re.ReplaceAllString(str, "")

	// 2. if any of the lines are not indented, return as we're already dedent-ed
	re = regexp.MustCompile(`(^|\r?\n)[^\t \n]`)
	if re.MatchString(str) {
		return str
	}

	// 3. find all line breaks to determine the highest common indentation level
	re = regexp.MustCompile(`\n[\t ]+`)
	matches := re.FindAllString(str, -1)

	// 4. remove the common indentation from all strings
	if matches != nil {
		size := len(matches[0]) - 1

		for _, match := range matches {
			if len(match)-1 < size {
				size = len(match) - 1
			}
		}

		re := regexp.MustCompile(`\n[\t ]{` + fmt.Sprint(size) + `}`)
		str = re.ReplaceAllString(str, "\n")
	}

	// 5. Remove leading whitespace.
	re = regexp.MustCompile(`^\r?\n`)
	str = re.ReplaceAllString(str, "")

	return str
}

// checks if two strings are equal, treating any occurrences of `%%` in the
// expected string to mean "any text"
func areEqual(t *testing.T, actual, expect string) bool {
	t.Helper()

	expect = regexp.QuoteMeta(expect)
	expect = strings.ReplaceAll(expect, "%%", ".+")

	re := regexp.MustCompile(`^` + expect + `$`)

	return re.MatchString(actual)
}

type cliTestCase struct {
	name         string
	args         []string
	wantExitCode int
	wantStdout   string
	wantStderr   string
}

func testCli(t *testing.T, tc cliTestCase) {
	t.Helper()

	stdoutBuffer := &bytes.Buffer{}
	stderrBuffer := &bytes.Buffer{}

	ec := run(tc.args, stdoutBuffer, stderrBuffer)
	// ec := run(tc.args, os.Stdout, os.Stderr)

	stdout := stdoutBuffer.String()
	stderr := stderrBuffer.String()

	if ec != tc.wantExitCode {
		t.Errorf("cli exited with code %d, not %d", ec, tc.wantExitCode)
	}

	if !areEqual(t, dedent(t, stdout), dedent(t, tc.wantStdout)) {
		t.Errorf("stdout\n got:\n%s\n\n want:\n%s", dedent(t, stdout), dedent(t, tc.wantStdout))
	}

	if !areEqual(t, dedent(t, stderr), dedent(t, tc.wantStderr)) {
		t.Errorf("stderr\n got:\n%s\n\n want:\n%s", dedent(t, stderr), dedent(t, tc.wantStderr))
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		{
			name:         "",
			args:         []string{""},
			wantExitCode: 1,
			wantStdout: `
				NAME:
					 osv-scanner - scans various mediums for dependencies and matches it against the OSV database

				USAGE:
					 osv-scanner [global options] command [command options] [directory1 directory2...]

				COMMANDS:
					 help, h  Shows a list of commands or help for one command

				GLOBAL OPTIONS:
					 --docker value, -D value [ --docker value, -D value ]      scan docker image with this name
					 --lockfile value, -L value [ --lockfile value, -L value ]  scan package lockfile on this path
					 --sbom value, -S value [ --sbom value, -S value ]          scan sbom file on this path
					 --config value                                             set/override config file
					 --json                                                     sets output to json (WIP) (default: false)
					 --skip-git                                                 skip scanning git repositories (default: false)
					 --recursive, -r                                            check subdirectories (default: false)
					 --help, -h                                                 show help (default: false)
			`,
			wantStderr: "",
		},
		// one specific supported lockfile
		{
			name:         "",
			args:         []string{"", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
			wantStdout: `
				Scanning dir ./fixtures/locks-many/composer.lock
        Scanned %%/fixtures/locks-many/composer.lock file and found 1 packages
			`,
			wantStderr: "",
		},
		// one specific unsupported lockfile
		{
			name:         "",
			args:         []string{"", "./fixtures/locks-many/not-a-lockfile.toml"},
			wantExitCode: 1,
			wantStdout: `
				Scanning dir ./fixtures/locks-many/not-a-lockfile.toml
				NAME:
					 osv-scanner - scans various mediums for dependencies and matches it against the OSV database

				USAGE:
					 osv-scanner [global options] command [command options] [directory1 directory2...]

				COMMANDS:
					 help, h  Shows a list of commands or help for one command

				GLOBAL OPTIONS:
					 --docker value, -D value [ --docker value, -D value ]      scan docker image with this name
					 --lockfile value, -L value [ --lockfile value, -L value ]  scan package lockfile on this path
					 --sbom value, -S value [ --sbom value, -S value ]          scan sbom file on this path
					 --config value                                             set/override config file
					 --json                                                     sets output to json (WIP) (default: false)
					 --skip-git                                                 skip scanning git repositories (default: false)
					 --recursive, -r                                            check subdirectories (default: false)
					 --help, -h                                                 show help (default: false)
			`,
			wantStderr: "",
		},
		// all supported lockfiles in the directory should be checked
		{
			name:         "",
			args:         []string{"", "./fixtures/locks-many"},
			wantExitCode: 0,
			wantStdout: `
				Scanning dir ./fixtures/locks-many
				Scanned %%/fixtures/locks-many/Gemfile.lock file and found 1 packages
				Scanned %%/fixtures/locks-many/composer.lock file and found 1 packages
				Scanned %%/fixtures/locks-many/yarn.lock file and found 1 packages
			`,
			wantStderr: "",
		},
		// all supported lockfiles in the directory should be checked
		{
			name:         "",
			args:         []string{"", "./fixtures/locks-many-with-invalid"},
			wantExitCode: 0,
			wantStdout: `
				Scanning dir ./fixtures/locks-many-with-invalid
				Scanned %%/fixtures/locks-many-with-invalid/Gemfile.lock file and found 1 packages
				Scanned %%/fixtures/locks-many-with-invalid/yarn.lock file and found 1 packages
			`,
			wantStderr: `
				Attempted to scan lockfile but failed: %%/fixtures/locks-many-with-invalid/composer.lock
			`,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			name:         "",
			args:         []string{"", "./fixtures/locks-one-with-nested"},
			wantExitCode: 0,
			wantStdout: `
				Scanning dir ./fixtures/locks-one-with-nested
				Scanned %%/fixtures/locks-one-with-nested/yarn.lock file and found 1 packages
			`,
			wantStderr: "",
		},
		// nested directories are checked when `--recursive` is passed
		{
			name:         "",
			args:         []string{"", "--recursive", "./fixtures/locks-one-with-nested"},
			wantExitCode: 0,
			wantStdout: `
				Scanning dir ./fixtures/locks-one-with-nested
				Scanned %%/fixtures/locks-one-with-nested/nested/composer.lock file and found 1 packages
				Scanned %%/fixtures/locks-one-with-nested/yarn.lock file and found 1 packages
			`,
			wantStderr: "",
		},
		// output with json
		{
			name:         "",
			args:         []string{"", "--json", "./fixtures/locks-many/composer.lock"},
			wantExitCode: 0,
			wantStdout: `
				{
					"results": []
				}
			`,
			wantStderr: `
				Scanning dir ./fixtures/locks-many/composer.lock
				Scanned %%/fixtures/locks-many/composer.lock file and found 1 packages
			`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}
