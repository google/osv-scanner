package config_test

import (
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	m.Run()

	testutility.CleanSnapshots(m)
}
