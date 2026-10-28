package output_test

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	// ensure SARIF artifact paths are not stripped when running on a GitHub runner
	_ = os.Unsetenv("GITHUB_WORKSPACE")

	m.Run()

	testutility.CleanSnapshots(m)
}
