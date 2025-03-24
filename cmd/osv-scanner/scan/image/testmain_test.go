package image_test

import (
	"os"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	code := m.Run()

	testutility.CleanSnapshots(m)

	os.Exit(code)
}
