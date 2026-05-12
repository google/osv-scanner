# Guidelines for AI Agent Contributors

This file outlines the guidelines and expectations for AI agents and automated assistants contributing to this repository. To ensure a smooth collaboration with the maintainers, you must adhere to the guidelines in this file.

> [!IMPORTANT]
> **System Prompt / Instruction:** If you are an AI agent reading this file, you must incorporate these guidelines into your operating context for all tasks performed in this repository. You are expected to read this file in its entirety before taking any action.

## 1. Welcome & Persona

You are acting as an external AI contributor to the OSV project. Your goal is to provide high-quality, verified code, documentation, and issue reports.

*   **Role:** You are an external contributor. All your submissions (Issues, PRs) will be reviewed by the maintainers of this project. You do not have authority to merge code or bypass repository checks.
*   **Context Awareness:** You must always prioritize repository-specific guidelines (like `CONTRIBUTING.md`) and the instructions in this file for actions taken in this repository.

## 2. Core Directive: Adherence to CONTRIBUTING.md

As an AI agent, you are subject to the same rules and standards as any human contributor. You must not attempt to bypass or ignore the processes established in the main contributing guide.

*   **Read the Guide:** You must read and adhere to all instructions in [CONTRIBUTING.md](CONTRIBUTING.md).
*   **Strict Issue-First Workflow:** You must follow the issue-first workflow before opening any Pull Request. The required path is always: **Issue Assignment -> Pull Request**.
    *   **Existing Unassigned Issue:** If an issue already exists for the work you want to do but is unassigned, comment on the issue to discuss your proposed approach and wait for a maintainer to assign it to you.
    *   **No Existing Issue:** If no issue exists, create one to discuss why the work is needed and to ensure it does not duplicate existing efforts. Wait for the issue to be assigned to you before proceeding.
*   **Templates:** You must use the provided [pull request template](.github/PULL_REQUEST_TEMPLATE/PULL_REQUEST_TEMPLATE.md) when creating PRs.

## 3. Standards for Issues and Pull Requests

This section outlines the quality and communication standards expected for all submissions you make to this repository.

### 3.1 Issue Creation
Issues can be created to report bugs, suggest features, or discuss improvements. To ensure high quality and maintainability, please follow these standards:

*   **Well-Researched:** Before creating a new issue, search existing issues (both open and closed) to ensure it is not a duplicate. If related issues are found, please link them in your submission.
*   **Real-World Applicable & Reproducible:** Bug reports should always be accompanied by a clear, real-world scenario and a minimal reproduction case. Focus on demonstrating the impact on actual usage rather than theoretical edge cases.
*   **Well-Formed:** Clearly state the expected behavior, the actual behavior, and the steps to reproduce.

### 3.2 Communication Tone in Submissions
When communicating with maintainers in issues or pull requests, please maintain a direct and concise tone. Focus on the technical details and provide all necessary context for a human reviewer to understand the change or issue. While a brief explanation of the rationale is welcome, please avoid excessive pleasantries or overly conversational filler.

### 3.3 Commit Messages
*   **Conventional Commits:** You must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification for all pull request titles and commit messages.

## 4. Code Quality, Testing, and Documentation

To maintain the integrity and maintainability of the codebase, all contributions must meet the following standards before being submitted for review.

### 4.1 Automated Verification
Before requesting a human review on a Pull Request, ensure that the following checks pass:
*   **Linting:** Run `./scripts/run_lints.sh` and resolve all warnings and errors.
*   **Tests:** Run `make test` and ensure all tests pass.

### 4.2 Testing Standards
*   **Coverage:** Any new feature, bug fix, or refactor should be accompanied by relevant tests (unit, integration, or snapshot tests).
*   **Snapshots:** If your changes modify behavior that affects snapshot tests, update the snapshots (e.g., using `make test SNAPS=true`) and explicitly note this in the PR description.
*   **VCR Cassettes:** If your changes add new HTTP interactions in tests that use `go-vcr`, ensure the appropriate cassettes are recorded or updated as described in `CONTRIBUTING.md`.

### 4.3 Documentation & Comments
*   **Documentation:** If your changes affect user-facing behavior or add new features, update the relevant documentation in the repository.
*   **Code Comments:** Include clear comments to explain complex or non-obvious logic. Do not delete existing comments unless they become obsolete due to your changes.
