// Package sourceanalysis provides functionality for performing source analysis on code.
package sourceanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/v2/internal/url"
	"github.com/google/osv-scanner/v2/internal/utility/pathfilter"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/vuln/scan"
	"google.golang.org/protobuf/encoding/protojson"
)

// errLocalDependencyUnavailable reports that call analysis could not run
// because a module or toolchain required by the project is not present on
// disk, or lacks a trusted checksum record. It is distinct from a scanner
// failure: vulnerability findings remain valid, but no reachability
// information was produced for them.
var errLocalDependencyUnavailable = errors.New("required module or toolchain unavailable locally")

// errIntegrityVerificationFailed reports that the module cache does not match
// the trusted go.sum records. This fails closed: no analysis is performed and
// the user is told that dependency integrity could not be established.
var errIntegrityVerificationFailed = errors.New("cached module failed integrity verification")

// integrityFailureMarkers are diagnostics emitted when cached module contents
// contradict a trusted checksum record.
var integrityFailureMarkers = []string{
	"checksum mismatch",
	"checksum error",
	// go mod verify compares the extracted directory (and the cached ZIP)
	// against the recorded hash and uses these exact diagnostics.
	"dir has been modified",
	"zip has been modified",
}

// localDependencyUnavailableMarkers are Go toolchain diagnostics that mean the
// build cannot be satisfied from local state. They are used only to choose an
// accurate diagnostic and to avoid fabricating negative reachability results;
// they never turn a genuine analysis failure into a skip.
var localDependencyUnavailableMarkers = []string{
	"module lookup disabled by goproxy=off",
	"gotoolchain=local",
	"go.mod requires go >=",
	"missing go.sum entry",
	"no required module provides package",
	"cannot find module providing package",
	"toolchain not available",
	// Vendor mode cannot answer module-graph queries, and inconsistent vendor
	// metadata makes offline analysis impossible without a rewrite.
	"can't compute 'all' using the vendor directory",
	"inconsistent vendoring",
}

// goOfflineEnv returns the environment additions that deny network access to
// the Go toolchain. Several variables are needed because independent
// toolchain features perform downloads:
//
//   - GOPROXY=off blocks module downloads (both proxies and direct VCS).
//   - GOTOOLCHAIN=local blocks automatic Go toolchain downloads.
//   - GOTELEMETRY=off blocks telemetry uploads.
//   - GOFLAGS gains -mod=readonly so a missing trusted checksum record can
//     never be resolved by editing go.sum after consulting the checksum
//     database (observed with an inherited GOFLAGS=-mod=mod).
//
// Module integrity verification (go.sum and the checksum database) is
// deliberately left enabled: cached modules are still verified, and no
// security check is weakened to achieve offline execution. -mod=readonly
// makes verification stricter, not weaker.
func goOfflineEnv(env []string) []string {
	offlineEnv := make([]string, 0, len(env)+4)
	offlineEnv = append(offlineEnv, env...)

	return append(offlineEnv,
		"GOPROXY=off",
		"GOTOOLCHAIN=local",
		"GOTELEMETRY=off",
		"GOFLAGS="+offlineGOFlags(env),
	)
}

// offlineGOFlags derives the GOFLAGS value used for offline analysis.
//
// All non-"-mod" entries are preserved so ordinary user settings (build tags,
// -modfile, etc.) keep working. Module mode is forced to readonly unless the
// user explicitly selected vendor mode: vendor mode reads dependencies from
// vendor/ and never accesses the network, while readonly guarantees that Go
// cannot rewrite go.mod/go.sum or resolve a missing go.sum entry through the
// checksum database. A user-specified -mod=mod is therefore replaced.
func offlineGOFlags(env []string) string {
	ambient := ""
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "GOFLAGS" {
			ambient = value
		}
	}

	fields := strings.Fields(ambient)
	kept := make([]string, 0, len(fields)+1)
	vendorMode := false

	for i := 0; i < len(fields); i++ {
		field := fields[i]
		switch {
		case field == "-mod":
			// Space-separated form; the value is the next field.
			if i+1 < len(fields) {
				i++
				if fields[i] == "vendor" {
					vendorMode = true
				}
			}
		case strings.HasPrefix(field, "-mod="):
			if strings.TrimPrefix(field, "-mod=") == "vendor" {
				vendorMode = true
			}
		default:
			kept = append(kept, field)
		}
	}

	if vendorMode {
		kept = append(kept, "-mod=vendor")
	} else {
		kept = append(kept, "-mod=readonly")
	}

	return strings.Join(kept, " ")
}

// explicitModFlag returns the -mod value explicitly requested in GOFLAGS, if
// any, and whether such a flag was present.
func explicitModFlag(env []string) (string, bool) {
	ambient := ""
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "GOFLAGS" {
			ambient = value
		}
	}

	fields := strings.Fields(ambient)
	for i := range fields {
		switch {
		case fields[i] == "-mod" && i+1 < len(fields):
			return fields[i+1], true
		case strings.HasPrefix(fields[i], "-mod="):
			return strings.TrimPrefix(fields[i], "-mod="), true
		}
	}

	return "", false
}

// usesVendorLayout reports whether a project has the vendor layout that Go
// selects automatically for modules declaring Go 1.14 or newer.
func usesVendorLayout(moddir string) bool {
	if _, err := os.Stat(filepath.Join(moddir, "vendor", "modules.txt")); err != nil {
		return false
	}

	gomod, err := os.ReadFile(filepath.Join(moddir, "go.mod"))
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(gomod), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "go" {
			continue
		}
		parts := strings.Split(fields[1], ".")
		major, minor := 0, 0
		if len(parts) > 0 {
			major, _ = strconv.Atoi(parts[0])
		}
		if len(parts) > 1 {
			minor, _ = strconv.Atoi(parts[1])
		}

		return major > 1 || (major == 1 && minor >= 14)
	}

	return false
}

// vendorModeEnabled reports whether offline analysis should use vendor mode,
// either explicitly requested by the user or selected automatically by Go.
func vendorModeEnabled(env []string, moddir string) bool {
	if value, explicit := explicitModFlag(env); explicit {
		return value == "vendor"
	}

	return usesVendorLayout(moddir)
}

// setEnvValue replaces the last occurrence of key in env, or appends it.
func setEnvValue(env []string, key, value string) []string {
	out := append([]string(nil), env...)
	for i := len(out) - 1; i >= 0; i-- {
		if k, _, ok := strings.Cut(out[i], "="); ok && k == key {
			out[i] = key + "=" + value

			return out
		}
	}

	return append(out, key+"="+value)
}

// goOfflineEnvForDir extends goOfflineEnv with directory-dependent vendor
// handling: an automatically selected vendor directory must not be changed
// into readonly module mode.
func goOfflineEnvForDir(env []string, moddir string) []string {
	offline := goOfflineEnv(env)
	if !usesVendorLayout(moddir) {
		return offline
	}
	if value, explicit := explicitModFlag(env); explicit && value != "vendor" {
		return offline
	}

	flags := strings.Fields(offlineGOFlags(env))
	kept := make([]string, 0, len(flags))
	for _, flag := range flags {
		if flag != "-mod=readonly" {
			kept = append(kept, flag)
		}
	}
	kept = append(kept, "-mod=vendor")

	return setEnvValue(offline, "GOFLAGS", strings.Join(kept, " "))
}

// classifyGoCommandError distinguishes an integrity failure, an unavailable
// local dependency, and a genuine scanner failure. Error text is preserved
// verbatim for the user and for diagnostics. Integrity failures are checked
// first because they must fail closed even if other wording is present.
func classifyGoCommandError(err error, stderr string) error {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = err.Error()
	} else {
		detail += ": " + err.Error()
	}

	lower := strings.ToLower(detail)
	for _, marker := range integrityFailureMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("%w: %s", errIntegrityVerificationFailed, detail)
		}
	}
	for _, marker := range localDependencyUnavailableMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("%w: %s", errLocalDependencyUnavailable, detail)
		}
	}

	return fmt.Errorf("govulncheck: %s", detail)
}

// classifyGovulncheckError preserves the original classifier name used by the
// govulncheck subprocess wrapper.
func classifyGovulncheckError(err error, stderr string) error {
	return classifyGoCommandError(err, stderr)
}

// goOfflineSubprocessEnv returns the environment used for offline Go
// toolchain subprocesses (preflight and analysis alike).
func goOfflineSubprocessEnv() []string {
	return goOfflineEnv(os.Environ())
}

// verifyOfflineModuleIntegrity establishes that the project can be analyzed
// using only locally available, trusted data:
//
//  1. every module in the build graph has a complete go.sum record, enforced
//     by `go list -m -json all` under -mod=readonly;
//  2. cached module contents match those records, enforced by `go mod verify`.
//
// Both commands fail without network access when data is missing or
// unverifiable; neither edits go.mod or go.sum. With GOPROXY=off and
// GOTOOLCHAIN=local they cannot fetch modules, toolchains, or checksums.
func verifyOfflineModuleIntegrity(moddir string) error {
	if vendorModeEnabled(os.Environ(), moddir) {
		// Module-cache checksums do not apply to vendor mode. Go itself rejects
		// missing or inconsistent vendor/modules.txt during package loading, and
		// GOPROXY=off prevents any network fallback. Skipping these module-only
		// checks preserves vendor mode without trusting unverified downloads.
		return nil
	}

	listCmd := exec.CommandContext(context.Background(), "go", "list", "-m", "-json", "all")
	listCmd.Dir = moddir
	listCmd.Env = goOfflineSubprocessEnv()
	var listStderr bytes.Buffer
	listCmd.Stderr = &listStderr
	if err := listCmd.Run(); err != nil {
		return classifyGoCommandError(err, listStderr.String())
	}

	verifyCmd := exec.CommandContext(context.Background(), "go", "mod", "verify")
	verifyCmd.Dir = moddir
	verifyCmd.Env = goOfflineSubprocessEnv()
	var verifyStderr bytes.Buffer
	verifyCmd.Stderr = &verifyStderr
	if err := verifyCmd.Run(); err != nil {
		return classifyGoCommandError(err, verifyStderr.String())
	}

	return nil
}

func goAnalysis(pkgs []models.PackageVulns, source models.SourceInfo, offline bool) {
	// TODO: This will be moved to enrichers which does have context.
	cmd := exec.CommandContext(context.TODO(), "go", "version")
	if offline {
		cmd.Env = goOfflineEnv(os.Environ())
	}
	_, err := cmd.Output()
	if err != nil {
		cmdlogger.Infof("Skipping call analysis on Go code since Go is not installed.")
		return
	}

	// Set GOVERSION to the Go version in go.mod.
	var goVersion string
	for _, pkg := range pkgs {
		if pkg.Package.Name == "stdlib" {
			goVersion = pkg.Package.Version
			break
		}
	}

	vulns, vulnsByID := vulnsFromAllPkgs(pkgs)
	// Filter out advisories with no symbol information first
	// This is purely an optimisation step, further filtering is done in matchAnalysisWithPackageVulns function
	filteredVulns := []*osvschema.Vulnerability{}
	for _, vuln := range vulns {
		if vulnHasImportsField(vuln, nil) {
			filteredVulns = append(filteredVulns, vuln)
		}
	}

	res, err := runGovulncheck(filepath.Dir(source.Path), filteredVulns, goVersion, offline)
	if err != nil {
		if errors.Is(err, errIntegrityVerificationFailed) {
			cmdlogger.Errorf(
				"Refusing Go call analysis on '%s' because dependency integrity could not be verified: %s. No reachability information was produced; the ordinary vulnerability findings are still reported.",
				source.Path,
				err.Error(),
			)

			return
		}

		if errors.Is(err, errLocalDependencyUnavailable) {
			// Analysis was skipped, not completed. Leave ExperimentalAnalysis
			// untouched so no vulnerability is reported as unreachable.
			cmdlogger.Warnf(
				"Skipping Go call analysis on '%s': %s. The package and vulnerability findings are still reported without call information; make the required modules and Go toolchain available locally to enable call analysis in --offline mode.",
				source.Path,
				err.Error(),
			)

			return
		}

		// TODO: Better method to identify the type of error and give advice specific to the error
		cmdlogger.Errorf(
			"Failed to run code analysis (govulncheck) on '%s' because %s\n"+
				"(the Go toolchain is required)", source.Path, err.Error(),
		)

		return
	}
	matchAnalysisWithPackageVulns(pkgs, res, vulnsByID)
}

func matchAnalysisWithPackageVulns(pkgs []models.PackageVulns, idToFindings map[string][]*govulncheck.Finding, vulnsByID map[string]*osvschema.Vulnerability) {
	idToModuleToCalled := map[string]map[string]bool{}
	for id, findings := range idToFindings {
		idToModuleToCalled[id] = map[string]bool{}
		for _, f := range findings {
			modulePath := f.Trace[0].Module
			called := f.Trace[0].Function != ""
			idToModuleToCalled[f.OSV][modulePath] = called
		}
	}

	for _, pv := range pkgs {
		// Use index to keep reference to original element in slice
		for groupIdx := range pv.Groups {
			for _, vulnID := range pv.Groups[groupIdx].IDs {
				analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
				if *analysis == nil {
					*analysis = make(map[string]models.AnalysisInfo)
				}

				moduleToCalled, ok := idToModuleToCalled[vulnID]
				if !ok { // If vulnerability not found, check if it contains any source information
					fillNotImportedAnalysisInfo(vulnsByID, vulnID, pv, analysis)
					continue
				}

				pkg := pv.Package
				if !vulnHasImportsField(vulnsByID[vulnID], &pkg) && moduleToCalled[pv.Package.Name] {
					// Vuln entry does not have any symbol information, therefore called being true is not useful
					continue
				}

				(*analysis)[vulnID] = models.AnalysisInfo{
					Called: moduleToCalled[pv.Package.Name],
				}
			}
		}
	}
}

func vulnHasImportsField(vuln *osvschema.Vulnerability, pkg *models.PackageInfo) bool {
	if vuln == nil {
		return false
	}
	for _, affected := range vuln.GetAffected() {
		if pkg != nil {
			// TODO: Compare versions to see if this is the correct affected element
			// ver, err := semantic.Parse(pv.Package.Version, semantic.SemverVersion)
			if affected.GetPackage().GetName() != pkg.Name {
				continue
			}
		}
		if affected.GetEcosystemSpecific() == nil {
			continue
		}
		_, hasImportsField := affected.GetEcosystemSpecific().GetFields()["imports"]
		if hasImportsField {
			return true
		}
	}

	return false
}

// fillNotImportedAnalysisInfo checks for any source information in advisories, and sets called to false
func fillNotImportedAnalysisInfo(vulnsByID map[string]*osvschema.Vulnerability, vulnID string, pv models.PackageVulns, analysis *map[string]models.AnalysisInfo) {
	if vulnHasImportsField(vulnsByID[vulnID], &pv.Package) {
		// If there is source information, then analysis has been performed, and
		// code does not import the vulnerable package, so definitely not called
		(*analysis)[vulnID] = models.AnalysisInfo{
			Called: false,
		}
	}
}

func runGovulncheck(moddir string, vulns []*osvschema.Vulnerability, goVersion string, offline bool) (map[string][]*govulncheck.Finding, error) {
	if offline {
		// Fail closed before analysis if the project cannot be verified from
		// local trusted records alone.
		if err := verifyOfflineModuleIntegrity(moddir); err != nil {
			return nil, err
		}
	}

	// Create a temporary directory containing all the vulnerabilities that
	// are passed in to check against govulncheck.
	//
	// This enables OSV scanner to supply the OSV vulnerabilities to run
	// against govulncheck and manage the database separately from vuln.go.dev.
	dbdir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	defer func() {
		rerr := os.RemoveAll(dbdir)
		if err == nil {
			err = rerr
		}
	}()

	root, err := os.OpenRoot(dbdir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	for _, vuln := range vulns {
		dat, err := protojson.Marshal(vuln)
		if err != nil {
			return nil, err
		}
		if err := root.WriteFile(pathfilter.FilterPath(vuln.GetId())+".json", dat, 0600); err != nil {
			return nil, err
		}
	}

	// this only errors if the file path is not absolute,
	// which paths from os.MkdirTemp should always be
	dbdirURL, _ := url.FromFilePath(dbdir)

	// Run govulncheck on the module at moddir and vulnerability database that
	// was just created.
	cmd := scan.Command(context.Background(), "-db", dbdirURL.String(), "-C", moddir, "-json", "./...")
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = append(os.Environ(), "GOVERSION=go"+goVersion)
	if offline {
		cmd.Env = goOfflineEnvForDir(cmd.Env, moddir)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, classifyGovulncheckError(err, stderr.String())
	}

	// Group the output of govulncheck based on the OSV ID.
	h := &osvHandler{
		idToFindings: map[string][]*govulncheck.Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}

	return h.idToFindings, nil
}

type osvHandler struct {
	idToFindings map[string][]*govulncheck.Finding
}

func (h *osvHandler) Finding(f *govulncheck.Finding) {
	h.idToFindings[f.OSV] = append(h.idToFindings[f.OSV], f)
}

func handleJSON(from io.Reader, to *osvHandler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := govulncheck.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		if msg.Finding != nil {
			to.Finding(msg.Finding)
		}
	}

	return nil
}
