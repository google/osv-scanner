package source_test

import (
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/google/osv-scanner/v2/internal/config"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	config.OSVScannerConfigName = "osv-scanner-test.toml"

	if err := ensureJavareachJar(); err != nil {
		panic(err)
	}

	cleanupGitFixtures, err := testcmd.SetupGitFixtures()

	if err != nil {
		cleanupGitFixtures()

		panic(err)
	}

	slog.SetDefault(slog.New(testlogger.New()))
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{source.Command}
	m.Run()

	cleanupGitFixtures()

	testutility.CleanSnapshots(m)
}

func ensureJavareachJar() error {
	const (
		jarRelativePath = "testdata/artifact/javareach_test.jar"
		encodedSuffix   = ".b64"
	)

	jarPath := filepath.FromSlash(jarRelativePath)

	if _, err := os.Stat(jarPath); err == nil {
		return nil
	}

	encoded, err := os.ReadFile(jarPath + encodedSuffix)
	if err != nil {
		return err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return err
	}

	return os.WriteFile(jarPath, decoded, 0o644)
}
