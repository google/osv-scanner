package testcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func CopyFileTo(t *testing.T, file, dir string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("could not read test file: %v", err)
	}

	dst := filepath.Join(dir, filepath.Base(file))
	if err := os.WriteFile(dst, b, 0600); err != nil {
		t.Fatalf("could not copy test file: %v", err)
	}

	return dst
}

// CopyFileFlagTo creates a copy of the file pointed to by the given flag (if present
// in the test case arguments) in the given directory, updating all references
// in the arguments before returning the new path.
//
// Values that include "does_not_exist" are assumed to be for testing when the
// flag is given the path to a file or directory that does not exist, and so
// are ignored as if the flag was not given a value at all
func CopyFileFlagTo(t *testing.T, tc Case, flagName string, dir string) string {
	t.Helper()

	flagValue := tc.findFirstValueOfFlag(flagName)

	if flagValue == "" || strings.Contains(flagValue, "does_not_exist") {
		return ""
	}

	newPath := CopyFileTo(t, flagValue, dir)

	for i := range tc.Args {
		tc.Args[i] = strings.ReplaceAll(tc.Args[i], flagValue, newPath)
	}

	return newPath
}
