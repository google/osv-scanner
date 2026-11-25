# Offline Call Analysis Audit — Issue #3319

## Commit identity

| Item | Value |
| --- | --- |
| Starting commit (upstream `main`) | `84976ca9f19810864f7de74cefb153919f4e663c` |
| Final commit | `84976ca9f19810864f7de74cefb153919f4e663c` (no commit was created) |
| Branch | `fix/offline-call-analysis-network-isolation` |
| Working tree | Modified, uncommitted; see `git status --porcelain` below |

No commit, push, PR, or issue comment was made (not authorized). The changes are
present in the working tree only.

## Preflight

1. Fetched upstream `main`; `HEAD` was `84976ca9f19810864f7de74cefb153919f4e663c` and the
   worktree was created from that exact SHA. The tree was clean beforehand.
2. Read issue #3319 and all comments (none). The issue is open, unassigned, has no
   `closed_by_pull_requests`, and was created 2026-11-21 by `dhananjaypai08`
   (`author_association: NONE`).
3. Searched open and merged PRs for the issue number and for "offline / call analysis /
   network". No open or recently merged PR implements this fix.
4. No maintainer or contributor claim: no assignee, no discussion, no linked PR. The
   reporter offered to send a PR "if one of the approaches above is acceptable"; none exists.
5. Inspected the current source at the starting SHA (not a cached/older version), including
   `PluginNetworkDisabled` population, `sourceanalysis.Run`, and the Go/Rust subprocess paths.
6. Starting SHA recorded above.
7. No pre-existing user changes existed; none were overwritten. A separate detached worktree
   at the same SHA was used for the pre-fix reproduction.

Note: repository `AGENTS.md` asks an AI contributor to comment on an unassigned issue and wait
for assignment before contributing upstream. This task explicitly prohibits external actions
(no PR, no push, no issue comment), so no issue comment was posted. That process step would be
required before submitting this work upstream.

## Root cause

`--offline` populates `ScannerActions.PluginNetworkDisabled` in
`cmd/osv-scanner/internal/helper/getters.go`. `--offline-vulnerabilities` populates only
`CompareOffline`. `buildVulnerabilityResults` passed only `CallAnalysisStates` to
`sourceanalysis.Run`; the offline state never reached `goAnalysis` or `rustAnalysis`. Both
analyzers launched subprocesses with the ambient environment:

* Go: `scan.Command(...)` inherited `os.Environ()` (`GOPROXY`, `GOTOOLCHAIN`, etc.), so a missing
  module was requested from the module proxy and a higher required Go version triggered a
  toolchain download. The request path contains the dependency name.
* Rust: `exec.CommandContext(..., "cargo", "build", ...)` ran unconditionally, including
  arbitrary `build.rs` code from the scanned repository.

The scalibr plugin path was already covered by `removeNetworkPluginsWhenOffline`; call analysis
is not a plugin and therefore escaped that protection.

## Modified files and rationale

| File | Rationale |
| --- | --- |
| `internal/sourceanalysis/sourceanalysis.go` | Adds explicit `Options{Offline bool}` and a private `run(...)` seam (default `exec.CommandContext`). No globals; production behavior unchanged when `Offline` is false. |
| `internal/sourceanalysis/go.go` | Applies offline env, `-mod=readonly` normalization, vendor-mode preservation, offline integrity preflight, and classification of trusted success / local unavailability / integrity failure; skips reachability updates when analysis is skipped. |
| `internal/sourceanalysis/rust.go` | Skips `cargo build` entirely in offline mode with an actionable warning; injectable command factory for test evidence. Online path unchanged. |
| `pkg/osvscanner/vulnerability_result.go` | Derives source-analysis options from `PluginNetworkDisabled` only, via `sourceAnalysisOptions`, keeping `--offline-vulnerabilities` distinct. |
| `internal/sourceanalysis/integration_test.go`, `rust_test.go` | Updated call sites for the new explicit parameters. |
| `internal/sourceanalysis/offline_test.go` (new) | Unit tests for env construction, error classification, Rust offline/online dispatch, and flag scoping. |
| `internal/sourceanalysis/offline_network_test.go` (new) | Logging-proxy tests proving zero Go proxy requests offline, nonzero online, no toolchain download, and successful analysis with local-only code. |
| `pkg/osvscanner/vulnerability_result_internal_test.go` | Integration tests: offline-option distinction and preservation of findings/no negative reachability when Rust analysis is skipped. |
| `internal/sourceanalysis/offline_sumdb_test.go` (new) | Checksum-database/proxy/toolchain instrumentation, trusted/missing/invalid checksum and tampered-cache tests. |
| `internal/sourceanalysis/offline_verification_test.go` (new) | Extracted-directory integrity, independent `go.sum` records, and vendor-mode compatibility regression tests. |

No dependencies, detectors, documentation, or public APIs were changed.

## Security behavior before and after

| Scenario | Before | After |
| --- | --- | --- |
| `--offline`, Go module missing from cache | Module proxy receives `.zip`/`.mod` requests (dependency names leak) | `GOPROXY=off`; zero requests; clear warning; findings preserved without reachability |
| `--offline`, higher required Go toolchain | Toolchain module downloaded through proxy | `GOTOOLCHAIN=local`; zero requests; classified as unavailable dependency |
| `--offline`, Rust call analysis | `cargo build` runs `build.rs`; registry/network access possible | cargo is never launched; actionable warning; ordinary scan preserved |
| `--offline-vulnerabilities` only | Call analysis online | Unchanged: still online (distinct flag semantics preserved) |
| Online | Normal behavior | Unchanged |

## Go offline policy

The subprocess environment is built with `goOfflineEnv`, which appends:

* `GOPROXY=off` — disables module downloads via proxy *and* direct VCS.
* `GOTOOLCHAIN=local` — disables automatic toolchain downloads.
* `GOTELEMETRY=off` — disables telemetry uploads.
* `GOFLAGS` normalized to `-mod=readonly` (all other flags preserved; explicit vendor mode kept)
  — prevents Go from editing `go.mod`/`go.sum` or resolving a missing checksum record by querying
  the checksum database.

`GOSUMDB`, `GONOSUMDB`, `GOPRIVATE`, and `GONOSUMCHECK` are deliberately **not** set:
module integrity verification and `go.sum` checks remain fully enabled. No security check was
weakened. Before analysis, `verifyOfflineModuleIntegrity` requires complete trusted checksum
records (`go list -m -json all`) and verifies cached contents against them (`go mod verify`).
Error classification distinguishes integrity failures, unavailable local dependencies, and
genuine failures; skipped analysis never fabricates `Called: false` results.

## Rust offline policy

`CARGO_NET_OFFLINE=true` was rejected as the guarantee: it only restricts Cargo's own registry
access and does not constrain arbitrary code in `build.rs`. Under `--offline` the scanner does
not start cargo at all. The warning explicitly names build scripts, network access, and the fact
that no reachability information is produced. Online behavior is unchanged.

## Go Checksum Database Isolation

**Commits:** initial SHA `84976ca9f19810864f7de74cefb153919f4e663c`; final SHA
`84976ca9f19810864f7de74cefb153919f4e663c` (no commit created; all work is in the working tree).

### Original risk

`GOPROXY=off` blocks module proxy traffic, but the Go toolchain has a separate network path: the
checksum database (`GOSUMDB`, default `sum.golang.org`). `modfetch.checkModSum` consults the
checksum database whenever a module's checksum is not already present in `go.sum`, and its
lookup path contains `module@version`. Earlier code inherited the ambient `GOFLAGS`; with
`GOFLAGS=-mod=mod`, a cached module with a missing `go.sum` entry caused Go to verify that module
against the checksum database, leaking dependency names during an `--offline` scan.

### Observed Go behavior (Go 1.27.3, loopback logging endpoints)

Measured with real `go` subprocesses and an explicit alternate sumdb URL
`GOSUMDB="sum.golang.org http://127.0.0.1:<port>"`:

| Configuration | Result | Proxy requests | Checksum DB requests |
| --- | --- | --- | --- |
| cached module, complete `go.sum`, `-mod=mod` | success | 0 | 0 (early return from `checkModSum`) |
| cached module, **empty `go.sum`**, `-mod=mod` | error `verifying module ... /lookup/... 404` | 0 | **1**: `/lookup/example.com/dep@v1.0.0` |
| cached module, empty `go.sum`, `-mod=readonly` | `go list ./...` succeeds (Go trusts the extracted cache), but `go list -m -json all` fails with `missing go.sum entry for go.mod file` | 0 | 0 |
| `go mod verify`, empty `go.sum` | attempts proxy **and** sumdb | 1 | 1 — therefore never called unless completeness is established first |
| corrupted cached zip + removed extracted dir, complete `go.sum` | `go mod verify` fails `zip: checksum error` | 0 | 0 |

A plain `go list ./...` does **not** enforce missing `go.sum` entries for cached modules.
`go list -m -json all` and `go mod verify` do, and neither touches the network when the trusted
records are complete.

### Final offline trust policy

1. **Trusted record present** — a module in the cache *and* covered by matching `go.sum`
   `h1:` and `/go.mod h1:` records is accepted; analysis proceeds offline.
2. **Trusted record missing** — `go list -m -json all` fails under `-mod=readonly`; the scanner
   skips Go call analysis, reports `errLocalDependencyUnavailable`, and never queries the
   checksum database or proxy.
3. **Module unavailable** — `GOPROXY=off` makes resolution fail locally; classified as
   `errLocalDependencyUnavailable`.
4. **Cached contents fail verification** — `go mod verify` fails (e.g. `zip: checksum error`);
   classified as `errIntegrityVerificationFailed`, logged as an error, analysis refused.
5. **Toolchain download required** — `GOTOOLCHAIN=local` makes resolution fail locally;
   classified as `errLocalDependencyUnavailable`; no download.

`GOSUMDB=off`, `GONOSUMDB`, `GOPRIVATE`, and checksum generation are never set by the scanner.
`GOFLAGS` is normalized to `-mod=readonly` while preserving unrelated flags. `go.mod`/`go.sum`
are never rewritten by the offline path.

### Network instrumentation methodology

`httptest.Server` stand-ins return 404 and record request paths. Tests configure both:
`GOPROXY=<proxy logger>` and `GOSUMDB="sum.golang.org <sumdb logger>"`. The production code
overrides `GOPROXY` to `off`, so any proxy request is a violation; `GOSUMDB` is inherited, so any
sumdb request reaches the logger. Toolchain traffic would appear as a `golang.org/toolchain`
path on either logger. Requests from test *fixture setup* use a separate loopback file proxy and
`GOSUMDB=off` and are not counted by these assertions.

### Evidence counts

| Scenario | Proxy | Checksum DB | Toolchain | Analysis result |
| --- | --- | --- | --- | --- |
| Cached module + complete `go.sum` | 0 | 0 | 0 | success, 3 call findings |
| Cached module + missing `go.sum` (ambient `-mod=mod`) | 0 | 0 | 0 | skipped, classified unavailable |
| Missing module + empty cache | 0 | 0 | 0 | skipped, classified unavailable |
| Corrupted cached zip (re-extraction forced) | 0 | 0 | 0 | integrity failure, no findings |
| `go 1.999.0` required toolchain | 0 | 0 | 0 | skipped, `GOTOOLCHAIN=local` in error |
| Online control, cold cache | 2 (`/example.com/dep/@v/v1.0.0.zip`, `.mod`) | 0 | 0 | online behavior intact |

Raw-Go control (bypassing scanner policy, `-mod=mod`): **1** checksum-DB request,
**0** proxy requests — demonstrating the vulnerability the policy closes.

### Before/after project-file hashes

Observed in the focused tests (SHA-256):

* `go.mod`: `b2f1d77c83b3f3a3d2e279e40290aa817b4a6da6ba71004564318b9871f66d11` before and after.
* `go.sum` (trusted fixture): `b120d20b7bcc40e8519e734e0d0c135cddf99172499eed44dbfab2a85fbb5926`
  after analysis; in the missing-checksum case the test deliberately writes an empty `go.sum`
  (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) and it is unchanged by
  the scan.
* No extra files appeared in the project directory in any offline scenario.

### Focused test results

All of the following passed with `-count=1`:

```text
go test ./internal/sourceanalysis/... -count=1                 # ok
go test ./pkg/osvscanner/... -short -count=1                    # ok
go vet ./...                                                    # exit 0
go build ./...                                                  # exit 0
golangci-lint v2.15.0 run ./...                                  # only 188 pre-existing CRLF/gofmt findings in untouched files
```

## A. Extracted Cache Integrity

**Actual Go behavior (Go 1.27.3 source and experiment):** `go mod verify`
(`cmd/go/internal/modcmd/verify.go:verifyMod`) reads `<module>@<version>.ziphash`, hashes the
cached ZIP with `dirhash.HashZip`, **and hashes the extracted directory with `dirhash.HashDir`**,
comparing both to the recorded hash. It reports `zip has been modified` or
`dir has been modified` and exits non-zero. The previous audit statement that extracted-only
tampering was undetectable was wrong.

**Experiment:** a deterministic fixture cached `example.com/dep@v1.0.0` through a loopback
file proxy; the ZIP hash and `.ziphash` bytes were recorded; only one file in the extracted
directory was changed. The scanner's exact offline verification sequence was then run with
local logging endpoints for both proxy and checksum database.

| Observation | Result |
| --- | --- |
| Cached ZIP hash before/after | unchanged |
| `.ziphash` metadata before/after | unchanged |
| `go mod verify` diagnostic | `dir has been modified` |
| Scanner classification (before fix) | generic `govulncheck` failure — wrong category |
| Scanner classification (after fix) | `errIntegrityVerificationFailed` |
| Call findings | none |
| Proxy / checksum DB / toolchain requests | 0 / 0 / 0 |
| `go.mod`, `go.sum`, project files | unchanged |

**Fix:** added `dir has been modified` and `zip has been modified` to
`integrityFailureMarkers` so this genuine Go integrity guarantee is surfaced as an integrity
failure rather than a generic scanner failure. Regression test:
`TestExtractedDirTamperDetected` in `offline_verification_test.go`, using an isolated cache copy
so the ZIP and metadata are never modified.

## B. go.sum Completeness

The two record types were tested independently with the cached module present. Every case used
separate local proxy/checksum-database loggers and a cold-cache control.

| Case | `go.sum` records | Observed error (exact toolchain output condensed) | Classification | Requests |
| --- | --- | --- | --- | --- |
| Both present | ZIP + `go.mod` | none; 3 call findings | success | 0/0/0 |
| ZIP checksum missing | `go.mod` only | `missing go.sum entry for module providing package example.com/dep` | `errLocalDependencyUnavailable` | 0/0/0 |
| `go.mod` checksum missing | ZIP only | `missing go.sum entry for go.mod file` | `errLocalDependencyUnavailable` | 0/0/0 |
| Both missing | none | `missing go.sum entry for go.mod file` | `errLocalDependencyUnavailable` | 0/0/0 |
| Invalid ZIP checksum | wrong `h1:` | `verifying example.com/dep@v1.0.0: checksum mismatch ... SECURITY ERROR` | `errIntegrityVerificationFailed` | 0/0/0 |
| Cold cache | both records present | `module lookup disabled by GOPROXY=off` | `errLocalDependencyUnavailable` | 0/0/0 |

No checksum was generated, no `go.sum` line was silently accepted, and project files were
unchanged in every case. The scanner does not rely on the presence of one record implying the
other; both missing-record classes fail closed and never produce negative reachability.
Regression test: `TestGoSumRecordIndependence`.

## C. Vendor Mode Compatibility

Tested with Go 1.27.3, fixture modules declaring `go 1.21`, and a vendor tree containing
`vendor/modules.txt` plus the dependency source. Effective `GOFLAGS` and results:

| Fixture | Effective offline GOFLAGS | Result | Requests |
| --- | --- | --- | --- |
| No vendor dir, cold cache | `-mod=readonly` | skipped (`module lookup disabled by GOPROXY=off`) | 0/0/0 |
| Valid vendor, no explicit flag (auto vendor) | `-mod=vendor` | 3 call findings | 0/0/0 |
| Valid vendor, `GOFLAGS=-mod=vendor` | `-mod=vendor` | 3 call findings | 0/0/0 |
| Valid vendor, `-tags=x -mod=vendor` | `-tags=x -mod=vendor` | 3 call findings | 0/0/0 |
| Inconsistent `vendor/modules.txt` | vendor preserved | skipped (`inconsistent vendoring`) | 0/0/0 |
| `-mod=vendor` without vendor dir | vendor preserved | skipped (`inconsistent vendoring`) | 0/0/0 |

**Root cause and fix:** forcing `-mod=readonly` changed Go's automatic vendor selection, and
the module-cache preflight (`go list -m -json all`, `go mod verify`) cannot run in vendor mode
(`go: can't compute 'all' using the vendor directory`) because vendor trees have no module-cache
checksums. Added `usesVendorLayout` (vendor/modules.txt + go directive >= 1.14) and
`goOfflineEnvForDir`, which preserves automatic and explicit vendor mode while leaving an
explicit non-vendor `-mod` untouched. `verifyOfflineModuleIntegrity` skips module-cache checks
in vendor mode; Go itself rejects inconsistent vendor metadata and, with `GOPROXY=off`, cannot
fall back to the network. Vendor diagnostics are classified as `errLocalDependencyUnavailable`.
Regression test: `TestVendorModeCompatibility` plus unit tests in `TestGoOfflineEnvVendorMode`.

## Test commands and actual results

Environment: Windows, Go 1.27.3 (`C:\Users\Rahim\AppData\Local\Temp\opencode\gotoolchain\go`),
`TEST_VCR_MODE=ReplayOnly` where VCR is involved.

| Command | Result |
| --- | --- |
| `gofmt -w` on all modified/new Go files; `gofmt -l` on those files | Clean (no output) |
| `git diff --check` | Pass (exit 0) |
| `go vet ./...` | Pass (exit 0) |
| `go test ./internal/sourceanalysis/... -count=1` (final code, including new A/B/C tests) | PASS — all tests in the package |
| `go test ./internal/sourceanalysis -run 'TestExtractedDirTamperDetected\|TestGoSumRecordIndependence\|TestVendorModeCompatibility' -v -count=1` | PASS — 1 + 6 + 6 cases; zero requests in all offline cases |
| `go build ./...` | Pass (exit 0) |
| `go test ./internal/sourceanalysis -run '<new offline tests>' -v -count=1` | All new tests PASS (Go: 0 proxy requests; online: 2 requests; toolchain: 0 requests; local-only: 3 findings, 0 requests) |
| `go test ./internal/sourceanalysis -run 'TestOfflineRunDispatchMakesNoProxyRequests' -count=1` | PASS; warning logged, no error log |
| `go test ./pkg/osvscanner ./cmd/osv-scanner/internal/helper -count=1` | PASS |
| `go test ./cmd/osv-scanner/... -short -count=1` | 2 snapshot failures: `<rootdir>` placeholder vs URL-encoded absolute path (`New%20folder%20%283%29`) — workspace-path artifact; all other CLI tests pass |
| `go test ./... -short -count=1` in the space-containing workspace | Snapshot failures only (`<rootdir>` path encoding) plus 3 pre-existing Windows file-lock failures in `Test_extractRlibArchive_*`. All other packages pass. |
| Full suite with **the same final code** in a space-free worktree (`TEST_VCR_MODE=ReplayOnly`) | PASS — every package `ok`, zero failures (see below) |
| `bash scripts/run_lints.sh` (golangci-lint v2.15.0) | 188 findings, all `gofmt` on untouched files due to CRLF checkout; 0 findings in modified/new files after `nlreturn`/`paralleltest` fixes |

Pre-fix reproduction (pristine baseline worktree, same logging-proxy test):
`runGovulncheck error: ... reading http://127.0.0.1:57987/example.invalid/leakmod/@v/v1.2.3.zip: 404 Not Found`;
proxy log: `[/example.invalid/leakmod/@v/v1.2.3.zip /example.invalid/leakmod/@v/v1.2.3.mod]`.
The same three `Test_extractRlibArchive_*` Windows cleanup failures reproduce on the pristine
baseline, so they are not caused by this change.

## Final full-suite verification

The final code (including lint fixes) was copied to a detached worktree at the same starting
SHA whose absolute path contains no spaces or parentheses, and the following was run:

```text
TEST_VCR_MODE=ReplayOnly go test ./... -short -count=1
```

Result with the final code (including checksum, extracted-cache, go.sum-completeness, and
vendor-mode tests): every package reported `ok` (including `internal/sourceanalysis`,
`internal/output`, `pkg/osvscanner`, and all `cmd/osv-scanner/...` packages); no `FAIL` lines.
This confirms that the failures seen in the primary workspace were caused solely by its path
containing spaces and parentheses (SARIF `<rootdir>` normalization) and by a Windows
file-handle cleanup quirk, not by this change.

Preflight re-check at the end of this task: upstream `main` is still `84976ca9`, issue #3319
is still open, unassigned, has zero comments and zero linked PRs. Two attempts to query PR search
failed with transient MCP connection errors, so no *new* competing PR evidence is available;
the issue's `closed_by_pull_requests` count remains zero.

## Network-isolation evidence

All network tests use an `httptest.Server` that records request paths and returns 404.

* Baseline (pre-fix): **2** requests for the missing module (`.zip`, `.mod`).
* Fixed, `--offline` equivalent, missing module: **0** requests; error
  `required module or toolchain unavailable locally: ... module lookup disabled by GOPROXY=off`.
* Fixed, `--offline`, `go 1.999.0`: **0** requests; error mentions `GOTOOLCHAIN=local`.
* Fixed, `--offline`, stdlib-only module: **3** call findings, **0** requests.
* Fixed, online control: **2** requests (same as baseline) — previous behavior retained.
* Rust offline: a recording command factory captured **0** subprocess creations; online control
  captured exactly one `cargo build --workspace --all-targets --release` with the required
  `RUSTFLAGS`.
* Scanner integration: offline Rust skip returned the vulnerability finding with no
  `ExperimentalAnalysis` entries and `IsCalled() == true` (not reported as unreachable).

## Compatibility assessment

* `--offline-vulnerabilities` remains independent: `sourceAnalysisOptions` reads only
  `PluginNetworkDisabled`; covered by unit tests and the pre-existing
  `TestGetCommonScannerActions_OfflineFlags`.
* Online scans are unchanged: same commands, same environment, same RUSTFLAGS.
* Cached/local dependencies still produce call analysis under `--offline`.
* Internal `sourceanalysis.Run` gained an options parameter; no exported scanner API changed.
* No snapshots were updated; no test was disabled.

## Remaining limitations

* Go isolation is enforced by Go toolchain environment semantics, not an OS-level network
  sandbox. A future toolchain feature that performs network I/O without honoring these
  variables could reintroduce a leak; the logging-proxy regression tests would detect it.
* Error classification uses Go diagnostic strings. Upstream wording changes may require
  updating `localDependencyUnavailableMarkers` or `integrityFailureMarkers`; unknown messages
  are treated as genuine scanner failures (fail closed, never as a skip).
* The offline preflight adds two Go subprocesses (`go list -m -json all`, `go mod verify`) per
  Go source in non-vendor mode. Very large module graphs will be slower, and projects that cannot
  produce complete local checksum records skip call analysis rather than analyze unverified
  dependencies. This is an intentional integrity-first trade-off.
* Vendor-mode integrity rests on Go's own `vendor/modules.txt` consistency checks, not on
  `go.sum` or `go mod verify`; the module-cache preflight is intentionally skipped there.
* `go mod verify` compares both the cached ZIP and the extracted directory against the cached
  `.ziphash` metadata. It does not re-verify `.ziphash` against `go.sum` on every run; the
  trusted `go.sum` records are enforced by the package-loading subprocess (and by the download
  path when data is first fetched). The earlier claim that extracted-directory tampering was
  undetectable was incorrect and has been superseded by section A below.
* `GOSUMDB` remains enabled in offline mode, but no request should be necessary because the
  preflight requires a complete trusted `go.sum`; the logging-endpoint tests verify zero
  checksum-database requests rather than relying on environment inspection.
* Rust call analysis is intentionally unavailable under `--offline`; users lose reachability
  information for Rust sources in that mode.
* `--offline --download-offline-databases` still intentionally downloads vulnerability
  databases; this is documented behavior and was not changed.
* Full-suite snapshot tests require a checkout path without spaces/parentheses on this
  platform; otherwise `<rootdir>` normalization fails for reasons unrelated to this change.
* Three existing `Test_extractRlibArchive_*` tests fail intermittently on Windows due to
  unclosed file handles during `t.TempDir()` cleanup; reproduced on the pristine baseline.

## Final acceptance verdict

**PASS** — for the call-analysis offline guarantee defined by issue #3319, including the
checksum-database gap. The pre-fix module-proxy leak and the `-mod=mod` checksum-database leak
were both reproduced experimentally. After the fix, module-proxy, checksum-database, and
toolchain request counts are exactly zero in every offline scenario; trusted checksums are
enforced, missing checksums and tampered caches fail closed, project files are unchanged,
vulnerability findings are preserved, online behavior is unchanged, and Rust offline behavior
is intact. This is not a claim that every possible network path in every OSV-Scanner mode is
isolated; the verdict is scoped to the paths exercised and evidenced above.
