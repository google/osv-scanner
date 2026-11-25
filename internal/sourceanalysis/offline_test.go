package sourceanalysis

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestGoOfflineEnv(t *testing.T) {
	t.Parallel()

	env := goOfflineEnv([]string{
		"GOPROXY=http://ambient-proxy.invalid",
		"GOTOOLCHAIN=auto",
		"GOTELEMETRY=on",
		"PATH=/usr/bin",
	})

	// As with os/exec, the last value for a key wins.
	got := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("malformed env entry %q", entry)
		}
		got[key] = value
	}

	for key, want := range map[string]string{
		"GOPROXY":     "off",
		"GOTOOLCHAIN": "local",
		"GOTELEMETRY": "off",
		"GOFLAGS":     "-mod=readonly",
		"PATH":        "/usr/bin",
	} {
		if got[key] != want {
			t.Errorf("env[%q] = %q, want %q", key, got[key], want)
		}
	}
	if _, hasSumDB := got["GOSUMDB"]; hasSumDB {
		t.Error("goOfflineEnv must not disable module integrity checks (GOSUMDB)")
	}
	if _, hasNoSumDB := got["GONOSUMDB"]; hasNoSumDB {
		t.Error("goOfflineEnv must not disable module integrity checks (GONOSUMDB)")
	}

	// The caller's slice must not be modified.
	original := []string{"GOPROXY=http://ambient-proxy.invalid"}
	_ = goOfflineEnv(original)
	if len(original) != 1 {
		t.Errorf("goOfflineEnv mutated its input: %v", original)
	}
}

func TestOfflineGOFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  []string
		want string
	}{
		{name: "no ambient flags", want: "-mod=readonly"},
		{
			name: "mutable module mode is replaced but other flags are preserved",
			env:  []string{"GOFLAGS=-tags=offline -mod=mod -v"},
			want: "-tags=offline -v -mod=readonly",
		},
		{
			name: "space separated mutable module mode is replaced",
			env:  []string{"GOFLAGS=-mod mod -tags=x"},
			want: "-tags=x -mod=readonly",
		},
		{
			name: "vendor mode is preserved",
			env:  []string{"GOFLAGS=-mod=vendor -tags=x"},
			want: "-tags=x -mod=vendor",
		},
		{
			name: "readonly mode stays readonly",
			env:  []string{"GOFLAGS=-mod=readonly"},
			want: "-mod=readonly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := offlineGOFlags(tt.env); got != tt.want {
				t.Errorf("offlineGOFlags(%v) = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}

func TestGoOfflineEnvVendorMode(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "vendor", "modules.txt"), []byte("# example.com/dep v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module example.com/consumer\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	auto := goOfflineEnvForDir([]string{"GOFLAGS=-tags=x"}, project)
	got := envMap(auto)["GOFLAGS"]
	if got != "-tags=x -mod=vendor" {
		t.Errorf("automatic vendor mode GOFLAGS = %q, want %q", got, "-tags=x -mod=vendor")
	}

	// An explicit non-vendor -mod must win over automatic vendor selection.
	explicit := goOfflineEnvForDir([]string{"GOFLAGS=-tags=x -mod=mod"}, project)
	got = envMap(explicit)["GOFLAGS"]
	if got != "-tags=x -mod=readonly" {
		t.Errorf("explicit -mod=mod GOFLAGS = %q, want %q", got, "-tags=x -mod=readonly")
	}

	noVendor := filepath.Join(t.TempDir(), "no-vendor")
	if err := os.MkdirAll(noVendor, 0o755); err != nil {
		t.Fatal(err)
	}
	if vendorModeEnabled(nil, noVendor) {
		t.Error("vendor mode enabled for a project without vendor/modules.txt")
	}
}

func envMap(env []string) map[string]string {
	out := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		out[key] = value
	}

	return out
}

func TestClassifyGovulncheckError(t *testing.T) {
	t.Parallel()

	baseErr := errors.New("exit status 1")
	tests := []struct {
		name             string
		stderr           string
		wantUnavailable  bool
		wantIntegrityErr bool
	}{
		{
			name:            "module missing from cache",
			stderr:          "go: example.invalid/leakmod@v1.2.3: module lookup disabled by GOPROXY=off",
			wantUnavailable: true,
		},
		{
			name:            "higher required toolchain",
			stderr:          "go: go.mod requires go >= 1.999.0 (running go 1.27.3; GOTOOLCHAIN=local)",
			wantUnavailable: true,
		},
		{
			name:            "missing checksum entry",
			stderr:          "go: missing go.sum entry for module providing package example.invalid/leakmod",
			wantUnavailable: true,
		},
		{
			name:             "corrupt cached module zip",
			stderr:           "example.com/dep v1.0.0: zip: checksum error",
			wantIntegrityErr: true,
		},
		{
			name:             "modified extracted module directory",
			stderr:           "example.com/dep v1.0.0: dir has been modified (/cache/example.com/dep@v1.0.0)",
			wantIntegrityErr: true,
		},
		{
			name:            "inconsistent vendoring",
			stderr:          "go: inconsistent vendoring in /project",
			wantUnavailable: true,
		},
		{
			name:            "vendor cannot compute all",
			stderr:          "go: can't compute 'all' using the vendor directory",
			wantUnavailable: true,
		},
		{
			name:            "genuine analysis failure",
			stderr:          "govulncheck: internal failure while decoding database",
			wantUnavailable: false,
		},
		{
			name:            "no diagnostics",
			stderr:          "",
			wantUnavailable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classifyGovulncheckError(baseErr, tt.stderr)
			if isIntegrity := errors.Is(got, errIntegrityVerificationFailed); isIntegrity != tt.wantIntegrityErr {
				t.Fatalf("errors.Is(err, errIntegrityVerificationFailed) = %v, want %v (err: %v)", isIntegrity, tt.wantIntegrityErr, got)
			}
			if isUnavailable := errors.Is(got, errLocalDependencyUnavailable); isUnavailable != tt.wantUnavailable {
				t.Fatalf("errors.Is(err, errLocalDependencyUnavailable) = %v, want %v (err: %v)", isUnavailable, tt.wantUnavailable, got)
			}
			if !strings.Contains(got.Error(), baseErr.Error()) {
				t.Errorf("classified error lost the original failure: %v", got)
			}
		})
	}
}

type recordedCommand struct {
	name string
	args []string
	cmd  *exec.Cmd
}

// recordingCommandFactory records every attempted subprocess without running a
// project-controlled binary. A skipped analysis must produce zero records.
func recordingCommandFactory(records *[]recordedCommand) commandFactory {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// An inert stand-in command. It must never be started by offline analysis.
		cmd := exec.CommandContext(ctx, "go", "version")
		*records = append(*records, recordedCommand{
			name: name,
			args: slices.Clone(args),
			cmd:  cmd,
		})

		return cmd
	}
}

func rustTestPackages() []models.PackageVulns {
	return []models.PackageVulns{
		{
			Package: models.PackageInfo{
				Name:      "smallvec",
				Version:   "1.0.0",
				Ecosystem: "crates.io",
			},
			Vulnerabilities: []*osvschema.Vulnerability{{Id: "RUSTSEC-TEST-0001"}},
			Groups: []models.GroupInfo{
				{IDs: []string{"RUSTSEC-TEST-0001"}},
			},
		},
	}
}

//nolint:paralleltest // Temporarily replaces the global command logger.
func TestRustOfflineSkipsCargoAndKeepsFindings(t *testing.T) {
	// Not parallel: the command logger is global for the duration of this check.
	oldLogger := cmdlogger.GlobalLogger
	var logs bytes.Buffer
	cmdlogger.GlobalLogger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { cmdlogger.GlobalLogger = oldLogger })

	var records []recordedCommand
	pkgs := rustTestPackages()
	source := models.SourceInfo{Path: "project/Cargo.lock", Type: "lockfile"}

	run(source, pkgs, map[string]bool{"rust": true}, Options{Offline: true}, recordingCommandFactory(&records))

	if len(records) != 0 {
		t.Fatalf("offline Rust analysis attempted %d subprocess(es): %+v", len(records), records)
	}

	output := logs.String()
	for _, want := range []string{"Skipping Rust call analysis", "build scripts", "--offline", source.Path} {
		if !strings.Contains(output, want) {
			t.Errorf("skip diagnostic does not contain %q: %s", want, output)
		}
	}

	for _, pv := range pkgs {
		for _, group := range pv.Groups {
			if len(group.ExperimentalAnalysis) != 0 {
				t.Errorf("skipped analysis wrote reachability information: %v", group.ExperimentalAnalysis)
			}
			if !group.IsCalled() {
				t.Error("skipped analysis must not mark a vulnerability as unreachable")
			}
		}
	}
}

func TestRustOnlineStillLaunchesCargoBuild(t *testing.T) {
	t.Parallel()

	var records []recordedCommand
	source := models.SourceInfo{Path: "project/Cargo.lock", Type: "lockfile"}

	run(source, rustTestPackages(), map[string]bool{"rust": true}, Options{}, recordingCommandFactory(&records))

	if len(records) != 1 {
		t.Fatalf("online Rust analysis attempted %d subprocesses, want 1: %+v", len(records), records)
	}
	if records[0].name != "cargo" {
		t.Errorf("subprocess = %q, want cargo", records[0].name)
	}
	wantArgs := []string{"build", "--workspace", "--all-targets", "--release"}
	if !slices.Equal(records[0].args, wantArgs) {
		t.Errorf("cargo args = %v, want %v", records[0].args, wantArgs)
	}
	if !slices.Contains(records[0].cmd.Env, RustFlagsEnv) {
		t.Errorf("cargo env is missing required RUSTFLAGS: %v", records[0].cmd.Env)
	}
}

func TestOfflineOptionIsScopedToSelectedLanguage(t *testing.T) {
	t.Parallel()

	var records []recordedCommand
	factory := recordingCommandFactory(&records)
	source := models.SourceInfo{Path: "project/Cargo.lock", Type: "lockfile"}

	// Rust call analysis disabled: even online mode must not launch cargo.
	run(source, rustTestPackages(), map[string]bool{"rust": false}, Options{}, factory)
	if len(records) != 0 {
		t.Fatalf("disabled Rust analysis attempted subprocesses: %+v", records)
	}
}
