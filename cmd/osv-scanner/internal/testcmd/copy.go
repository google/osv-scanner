package testcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func CopyFile(from, to string) (string, error) {
	b, err := os.ReadFile(from)
	if err != nil {
		return "", fmt.Errorf("could not read test file: %w", err)
	}

	if err := os.WriteFile(to, b, 0600); err != nil {
		return "", fmt.Errorf("could not copy test file: %w", err)
	}

	return to, nil
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

	newPath, err := CopyFile(flagValue, filepath.Join(dir, filepath.Base(flagValue)))

	if err != nil {
		t.Fatalf("%v", err)
	}

	for i := range tc.Args {
		tc.Args[i] = strings.ReplaceAll(tc.Args[i], flagValue, newPath)
	}

	return newPath
}
