package resolution_test

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
)

func TestMain(m *testing.M) {
	code := m.Run()

	testutility.CleanSnapshots(m)

	os.Exit(code)
}
