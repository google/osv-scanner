package lockfile_test

import (
	"os"
	"strings"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func numberOfLockfileParsers(t *testing.T) int {
	t.Helper()

	directories, err := os.ReadDir(".")

	if err != nil {
		t.Fatalf("unable to read current directory: ")
	}

	count := 0

	for _, directory := range directories {
		if strings.HasPrefix(directory.Name(), "parse-") &&
			!strings.HasSuffix(directory.Name(), "_test.go") {
			count++
		}
	}

	return count
}

func TestKnownEcosystems(t *testing.T) {
	t.Parallel()

	expectedCount := numberOfLockfileParsers(t)

	// - npm, yarn, and pnpm,
	// - pip, poetry, pdm and pipenv,
	// - maven, gradle, and gradle/verification-metadata
	// all use the same ecosystem so "ignore" those parsers in the count
	expectedCount -= 7

	ecosystems := lockfile.KnownEcosystems()

	if knownCount := len(ecosystems); knownCount != expectedCount {
		t.Errorf("Expected to know about %d ecosystems, but knew about %d", expectedCount, knownCount)
	}

	uniq := make(map[lockfile.Ecosystem]int)

	for _, ecosystem := range ecosystems {
		uniq[ecosystem]++

		if uniq[ecosystem] > 1 {
			t.Errorf(`Ecosystem "%s" was listed more than once`, ecosystem)
		}
	}
}
