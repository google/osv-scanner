package osvscanner_test

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/internal/testsnapshot"
)

func TestMain(m *testing.M) {
	code := m.Run()

	testsnapshot.Clean(m)

	os.Exit(code)
}
