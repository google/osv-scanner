//go:build linux

package osvscanner

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"golang.org/x/sys/unix"
)

func TestDoScanWithoutHostRootReadPermission(t *testing.T) {
	t.Parallel()

	const stageEnv = "OSV_SCANNER_TEST_LANDLOCK_STAGE"
	const dirEnv = "OSV_SCANNER_TEST_LANDLOCK_DIR"

	switch os.Getenv(stageEnv) {
	case "restrict":
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		attr := struct{ handledAccessFS uint64 }{unix.LANDLOCK_ACCESS_FS_READ_DIR}
		fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
		if errno != 0 {
			t.Fatal(errno)
		}
		parent, err := unix.Open(os.Getenv(dirEnv), unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		rule := make([]byte, 12)
		binary.NativeEndian.PutUint64(rule, unix.LANDLOCK_ACCESS_FS_READ_DIR)
		if parent >= 0 && parent <= 1<<31-1 {
			binary.NativeEndian.PutUint32(rule[8:], uint32(parent))
		} else {
			t.Fatalf("directory descriptor does not fit the Landlock ABI: %d", parent)
		}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0)
		if errno != 0 {
			t.Fatal(errno)
		}
		if err := unix.Close(parent); err != nil {
			t.Fatal(err)
		}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
		if errno != 0 {
			t.Fatal(errno)
		}
		if err := unix.Close(int(fd)); err != nil {
			t.Fatal(err)
		}
		env := os.Environ()
		for i, value := range env {
			if strings.HasPrefix(value, stageEnv+"=") {
				env[i] = stageEnv + "=scan"
			}
		}
		// Re-exec after restriction so every Go runtime thread inherits the policy.
		if err := unix.Exec(os.Args[0], os.Args, env); err != nil {
			t.Fatal(err)
		}
	case "scan":
		root, err := os.OpenRoot("/")
		if err == nil {
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			t.Fatal("Landlock did not restrict opening the host root")
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatal(err)
		}
		actions := ScannerActions{
			LockfilePaths:         []string{filepath.Join(os.Getenv(dirEnv), "go.mod")},
			PluginNetworkDisabled: true,
			ShowAllPackages:       true,

			PluginsNoDefaults: true,
			PluginsEnabled:    []string{"go/gomod"},
			PluginsDisabled:   []string{"vulnmatch/osvdev"},
		}
		actions.TransitiveScanning.Disabled = true
		result, err := DoScan(actions)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Results) != 1 || len(result.Results[0].Packages) != 1 {
			t.Fatalf("unexpected scan results: %+v", result.Results)
		}
		pkg := result.Results[0].Packages[0].Package
		if pkg.Name != "github.com/BurntSushi/toml" || pkg.Version != "1.0.0" || pkg.Ecosystem != "Go" {
			t.Fatalf("unexpected extracted package: %+v", pkg)
		}
	default:
		_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
		if errno != 0 {
			testutility.Skip(t, "Landlock unavailable:", errno)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\nrequire github.com/BurntSushi/toml v1.0.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{"-test.run=^TestDoScanWithoutHostRootReadPermission$", "-test.v"}
		if testing.CoverMode() != "" {
			// Coverage builds otherwise create an unreadable directory outside the Landlock rule.
			coverDir := filepath.Join(dir, "cover")
			if err := os.Mkdir(coverDir, 0o700); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-test.gocoverdir="+coverDir)
		}
		cmd := exec.CommandContext(t.Context(), os.Args[0], args...) //nolint:gosec // Re-exec only this test binary, never user-supplied code.
		cmd.Env = append(os.Environ(), stageEnv+"=restrict", dirEnv+"="+dir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("restricted scan failed: %v\n%s", err, output)
		}
		t.Logf("%s", output)
	}
}
