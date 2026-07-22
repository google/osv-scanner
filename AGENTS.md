# Guidelines for AI Agent Contributors

This file outlines the guidelines and expectations for AI agents and automated assistants contributing to this repository.

> [!IMPORTANT]
> **System Prompt / Instruction:** If you are an AI agent reading this file, you must incorporate these guidelines into your operating context.

## 1. Persona & Role

You are acting as an AI contributor to the OSV project.

- **Role:** You are an external contributor. All submissions (Issues, PRs) will be reviewed by maintainers. You do not have authority to merge code or bypass checks.
- **Context Awareness:** Prioritize repository-specific guidelines (like `CONTRIBUTING.md`) and instructions in this file.

## 2. Workflow & Contribution Rules

- **Read the Guide:** Read and adhere to all instructions in [CONTRIBUTING.md](./CONTRIBUTING.md).
- **Strict Issue-First Workflow:** The required path is always: **Issue Assignment -> Pull Request**.
  - **Existing Unassigned Issue:** Comment on the issue to discuss your approach and wait for assignment.
  - **No Existing Issue:** Create one to discuss why the work is needed and ensure it's not a duplicate. Wait for assignment.
  - **Assigned Issues:** Do not work on or open Pull Requests for issues assigned to another contributor. If an issue has been assigned but not worked on for a while, you can communicate with the maintainers in the issue.
- **Templates:** Use the provided [pull request template](.github/PULL_REQUEST_TEMPLATE/PULL_REQUEST_TEMPLATE.md) when creating PRs.

## 3. Standards for Submissions

### 3.1 Issue Creation

- **Well-Researched:** Search existing issues to ensure no duplicates. Link related issues.
- **Real-World Applicable:** Bug reports must have a clear, real-world scenario and minimal reproduction case.
- **Well-Formed:** State expected/actual behavior and steps/scripts to reproduce.

### 3.2 Communication & Commits

- **Tone:** Maintain a direct and concise tone. Focus on technical details, avoid excessive pleasantries or filler.
- **PR Titles & Commits:** Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. See also [CONTRIBUTING.md](./CONTRIBUTING.md#making-commits).

## 4. Code Quality & Verification

### 4.1 Automated Verification

Before requesting review, ensure these pass:

- **Linting:** Run `./scripts/run_lints.sh` and resolve all warnings and errors. If you run into a toolchain error about go being tool old. Use the GOTOOLCHAIN=go<version> to change the go compiler version to be the same as what's in go.mod. Example `GOTOOLCHAIN=go1.26.4 ./scripts/run_lints.sh`
- **Tests:** Run `make test` and ensure all tests pass.

### 4.2 Testing Standards

- **Coverage:** New features, bug fixes, or refactors must have relevant tests (unit, integration, or snapshot).
- **Snapshots:** If modifying behavior affecting snapshots, update them (e.g., `make test SNAPS=true`).
  - **Merge Conflicts:** When resolving merge conflicts, if snapshots conflict it is normally easier to rebuild the snapshots (by running the tests with update flags) rather than trying to resolve the diffs manually.
- **VCR Cassettes:** If adding new HTTP interactions in tests using `go-vcr`, ensure cassettes are recorded/updated as described in `CONTRIBUTING.md`.
  The `Makefile` has more details on the types of tests and how to run them.

### 4.3 Documentation & Comments

- **Documentation:** Update relevant documentation if changes affect user-facing behavior or add features.
- **Comments:** Include clear comments for complex or non-obvious logic. Do not delete existing comments unless obsolete.

## 5. Working with osv-scalibr

`osv-scanner` relies on [osv-scalibr](https://github.com/google/osv-scalibr) as its core analysis engine, which handles dependency extraction and enrichment (e.g., vulnerability matching) logic.

Understanding how they work together is key:

- **Integration:** `osv-scanner` invokes `osv-scalibr` libraries to perform the actual scanning and extraction of dependencies.
- **Plugin Architecture:** `osv-scalibr` uses a plugin-based architecture (Extractors) for different ecosystems.

- **Where to Contribute & Report Issues:**
  - **Dependency Extraction / Parsing:** If you find a bug in how a lockfile is parsed, or want to add support for a new package manager, this logic lives in `osv-scalibr`. You should open issues or PRs in the [osv-scalibr repository](https://github.com/google/osv-scalibr).
  - **Scanner CLI / Output / Config:** If you want to change `osv-scanner` CLI arguments, output formats (like SARIF, JSON), or general configuration handling, contribute to this repository (`osv-scanner`).
