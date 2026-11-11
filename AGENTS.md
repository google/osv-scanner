# Guidelines for AI Agent Contributors

This file outlines the guidelines and expectations for AI agents and automated assistants contributing to `osv-scanner`.

> [!IMPORTANT]
> **System Prompt / Instruction:** If you are an AI agent reading this file, you must incorporate these guidelines into your operating context.

## 1. Persona & Role

You are acting as an AI contributor to the OSV project.

- **Role:** Unless acting on behalf of a project maintainer, you are an external contributor. Maintainers review all submissions (issues and pull requests). You do not have authority to merge code or bypass checks.
- **Context Awareness:** Prioritize repository-specific guidelines in this file, [CONTRIBUTING.md](./CONTRIBUTING.md), and [llms.txt](./llms.txt).

## 2. Workflow & Contribution Rules

- **Read the Guide:** Read and adhere to all instructions in [CONTRIBUTING.md](./CONTRIBUTING.md).
- **Strict Issue-First Workflow:** External contributors must follow **Issue Assignment → Pull Request** (project maintainers and agents acting on their behalf are exempt and can open pull requests directly without a prior issue or assignment):
  - **Existing Unassigned Issue:** Comment on the issue to discuss your proposed approach and wait for maintainer assignment.
  - **No Existing Issue:** Open an issue explaining why the change is needed after checking for duplicates, then wait for assignment.
  - **Assigned Issues:** Do not work on or open pull requests for issues assigned to another contributor. If an assigned issue appears stale, ask the maintainers on the issue first.
- **Templates:** Use the [pull request template](./.github/PULL_REQUEST_TEMPLATE/PULL_REQUEST_TEMPLATE.md) when opening pull requests.

## 3. Standards for Submissions

### 3.1 Issue Creation

- **Well-Researched:** Search existing issues to avoid duplicates and link related issues.
- **Real-World Applicable:** Bug reports must describe a concrete, real-world scenario with a minimal reproduction case.
- **Well-Formed:** Clearly state expected behavior, actual behavior, and exact reproduction steps.

### 3.2 Communication, Naming, & Commits

- **Tone:** Keep communication direct, technical, and concise. Avoid filler or excessive pleasantries.
- **PR Titles & Commits:** Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification (enforced on PR titles in CI). See [CONTRIBUTING.md](./CONTRIBUTING.md#making-commits).
- **Experimental CLI Flags:** Prefix new experimental CLI flags with `--x-` (for example, `--x-plugins`), not the deprecated `--experimental-` prefix. See [docs/experimental.md](./docs/experimental.md).
- **Allowed Filenames:** CI rejects file and directory names containing characters outside `[#@A-Za-z0-9._-]`. Avoid spaces, colons, parentheses, or other special characters in filenames and subtest names that generate cassette files.

## 4. Code Quality & Verification

### 4.1 Automated Verification

Before requesting review, verify that all local checks matching CI pass:

- **Linting:** Run `./scripts/run_lints.sh` (or `make lint`, and `make lint-fix` for autofixes) and resolve all warnings and errors. If your local Go binary is older than `go.mod`, set `GOTOOLCHAIN=go<version>` to match the `go` directive in `go.mod`.
- **Formatting:** Run `make format` (`./scripts/run_formatters.sh`) to format Markdown, YAML, JSON, and HTML files with Prettier.
- **Go Modules:** Run `go mod tidy` whenever imports or dependencies change; CI enforces `go mod tidy -diff`.
- **Snapshot Cleanup:** Run `./scripts/report_uncleaned_snapshots.py` when adding snapshots to a package. Every package with a `__snapshots__/` directory must define `TestMain` in `testmain_test.go` calling `testutility.CleanSnapshots(m)`.
- **Tests:** Run `make test` for the default fast suite, and run relevant extended suites (`SHORT=false`, `ACC=true`) when modifying integration, long-running, or container scanning behavior.
- **Workflows & Markdown Links:**
  - Modifications to `.github/workflows/**` are scanned with `zizmor`: pin third-party actions to full commit SHAs, set `persist-credentials: false` on `actions/checkout`, and declare minimal job-level `permissions`.
  - Modifications to `*.md` files are checked for broken links in CI.

### 4.2 Testing Standards

See the [Makefile](./Makefile) (`make help`) for all test targets and environment flags.

- **Coverage:** Include unit, integration, or snapshot tests for all new features, bug fixes, and refactors.
- **Snapshots (`go-snaps`):**
  - Default `make test` runs with `SHORT=true` and `ACC=false`, so `make test SNAPS=true` skips long-running and acceptance tests. Use `make update-snapshots` (`SNAPS=true ACC=true SHORT=false`) to update snapshots across the full test suite, or `make refresh-all` to refresh VCR cassettes, offline databases, and snapshots together.
  - CLI command tests capture labeled `stdout` and `stderr` snapshots via `testcmd.RunAndMatchSnapshots`.
  - **Skipping Snapshot Tests:** Never call `t.Skip()` or `t.SkipNow()` directly in packages that use snapshots, because `CleanSnapshots` will treat skipped snapshots as obsolete and fail. Always use `testutility.Skip`, `testutility.SkipIfShort`, or `testutility.SkipIfNotAcceptanceTesting`.
  - **Merge Conflicts:** Rebuild conflicting `.snap` files by re-running snapshot updates rather than resolving snapshot diffs manually.
- **VCR Cassettes & Pinned Severities:**
  - `cmd` tests record HTTP requests to `testdata/cassettes/<Test>.yaml` (`go-vcr`) and `deps.dev` unary gRPC calls to `testdata/cassettes/<Test>_grpc.yaml` (`internal/grpcvcr`).
  - Live `/v1/vulns/` lookups normalize severity scores against `cmd/osv-scanner/internal/testcmd/testdata/vuln_severities.json`.
  - CI runs with `VCR=ReplayOnly` and fails on missing interactions or unrecorded vulnerability severities. Commit all updated `.yaml`, `_grpc.yaml`, and `vuln_severities.json` files alongside test changes.
- **Mocked Offline Databases:**
  - Offline database tests build `.zip` archives in memory from JSON fixtures in `cmd/osv-scanner/internal/testcmd/testdata/offline-dbs/` (filtered by `allowedVulnIDs` in `cmd/osv-scanner/internal/testcmd/vcr.go`). Use `make update-offline-dbs` (`UPDATE_DBS=true`) when updating offline database fixtures.
- **Container Image E2E Tests:**
  - Image test fixtures live as `cmd/osv-scanner/scan/image/testdata/test-*.Dockerfile` and are built into `.tar` archives by `./scripts/build_test_images.sh` (run automatically when `ACC=true`). Do not commit generated `.tar` archives (`make clean` removes them).
- **Vulnerable Test Fixtures (`osv-scanner.toml`):**
  - CI scans this repository with `osv-scanner`. When adding vulnerable lockfiles or manifests under a new `testdata/` directory, add an `osv-scanner.toml` (for example, `[[PackageOverrides]]` with `ignore = true`) in that directory so repository self-scans do not fail.

### 4.3 Documentation & Comments

- **Documentation:** Update user-facing docs under `docs/` when changing CLI flags, configuration options, supported ecosystems, or output behavior, then run `make format`.
- **Comments:** Add clear comments for non-obvious logic. Do not remove existing comments unless they are obsolete.

## 5. Working with osv-scalibr

`osv-scanner` uses [osv-scalibr](https://github.com/google/osv-scalibr) end-to-end as its core scanning and analysis engine:

- **What lives in `osv-scalibr`:** Ecosystem lockfile/artifact extractors, vulnerability matching (`vulnmatch/osvdev`, `vulnmatch/osvlocal`), license matching, transitive dependency resolution (`pom.xml`, `requirements.txt`), guided remediation (`guidedremediation`), package deprecation enrichment, JAR reachability, OS package annotators, and security detectors.
- **What lives in `osv-scanner`:** CLI commands (`scan`, `fix`, `update`, `experimental-mcp`) and `osv-reporter` binary, plugin preset resolution (`internal/scalibrplugin/`), shared HTTP/gRPC client factories (`internal/scalibr/`), package/config filtering (`internal/scalibrannotator/filter/`), repo-specific extractors (`internal/scalibrextract/`, such as `gitrepo`, `vendored`, `nodemodules`, `osvscannerjson`), Go/Rust source call analysis (`internal/sourceanalysis/`), and output formatting (`internal/output/`, `internal/reporter/`).
- **Where to Contribute & Report Issues:**
  - **Dependency Extraction / Matching / Enrichment / Guided Remediation:** Open issues or PRs in [google/osv-scalibr](https://github.com/google/osv-scalibr) for lockfile/artifact parsing bugs, new ecosystem extractors, upstream enricher logic, or guided remediation engine changes.
  - **Scanner CLI / Presets / Output / Config:** Contribute to this repository (`osv-scanner`).

### Wiring a New `osv-scalibr` Extractor into `osv-scanner`

Plugins in `osv-scalibr` are not enabled automatically in `osv-scanner`. After an extractor merges into `osv-scalibr`, wire it in across these locations:

1. **Update dependency:** Bump `github.com/google/osv-scalibr` in `go.mod` and run `go mod tidy`.
2. **Register in presets:** Import and add the extractor to the appropriate preset in `internal/scalibrplugin/presets.go` (or gate behind an `--x-` flag in `pkg/osvscanner/scan.go` if experimental), and update `internal/scalibrplugin/resolve_test.go` (if modifying `artifact`) and `internal/scalibrplugin/__snapshots__/resolve_test.snap`.
3. **Map `-L` parse-as name:** If adding a lockfile or manifest extractor, add its parse-as mapping to `osvscannerScalibrExtractionMapping` in `pkg/osvscanner/internal/scanners/lockfile.go`.
4. **Update docs:** Add the artifact or manifest to [docs/supported_languages_and_lockfiles.md](./docs/supported_languages_and_lockfiles.md).
5. **Add E2E tests:** Add fixtures, VCR cassettes, `osv-scanner.toml` testdata ignores (if vulnerable), and snapshots under `cmd/osv-scanner/scan/`.

## 6. Documentation & Reference Index

Consult these repository documents when working on specific areas:

| Use Case                                                     | Documentation                                                                                                                              |
| :----------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture overview, scan flow, & repository map           | [llms.txt](./llms.txt)                                                                                                                     |
| General contribution rules, CLA, & local setup               | [CONTRIBUTING.md](./CONTRIBUTING.md)                                                                                                       |
| Build, lint, format, snapshot, & test targets                | [Makefile](./Makefile)                                                                                                                     |
| Previewing Jekyll docs locally & formatting docs             | [docs/README.md](./docs/README.md)                                                                                                         |
| Supported lockfiles, manifests, C/C++, & container artifacts | [docs/supported_languages_and_lockfiles.md](./docs/supported_languages_and_lockfiles.md)                                                   |
| Plugin presets, detectors, & `--x-plugins` flags             | [docs/manual-plugin-selection.md](./docs/manual-plugin-selection.md)<br>[docs/migrating-from-scalibr.md](./docs/migrating-from-scalibr.md) |
| Experimental features & `--x-` flag conventions              | [docs/experimental.md](./docs/experimental.md)                                                                                             |
| `osv-scanner.toml` schema, ignores, & package overrides      | [docs/configuration.md](./docs/configuration.md)                                                                                           |
| Output formats (table, JSON, SARIF, HTML, CycloneDX, SPDX)   | [docs/output.md](./docs/output.md)                                                                                                         |
| Source & container image scanning CLI behavior               | [docs/scan-source.md](./docs/scan-source.md)<br>[docs/scan-image.md](./docs/scan-image.md)                                                 |
| Guided remediation (`fix` and `update` subcommands)          | [docs/guided-remediation.md](./docs/guided-remediation.md)                                                                                 |
| Offline scanning & local vulnerability databases             | [docs/offline-mode.md](./docs/offline-mode.md)                                                                                             |
| GitHub Actions workflows & `osv-reporter` CI diffing         | [docs/github-action.md](./docs/github-action.md)<br>[docs/osv-reporter.md](./docs/osv-reporter.md)                                         |
| MCP server subcommand (`experimental-mcp`)                   | [cmd/osv-scanner/mcp/command.go](./cmd/osv-scanner/mcp/command.go)                                                                         |
