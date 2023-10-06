---
layout: page
title: GitHub Action
permalink: /github-action/
nav_order: 6
---

# GitHub Action

{: .no_toc }

OSV-Scanner is offered as a GitHub Action. We currently have two different GitHub Actions:

1. An action that performs a single vulnerability scan, which can be configured to scan on a [regular schedule](./github-action.md#scheduled-scans), or used as a check [on releases](./github-action.md#scan-on-release) to prevent releasing with known vulnerabilities in dependencies.
2. An action that triggers a scan with each [pull request](./github-action.md#scans-on-prs) and will only check for new vulnerabilities introduced through the pull request.

## Scheduled scans

Regularly scanning your project for vulnerabilities can alert you to new vulnerabilities in your dependency tree. This GitHub Action will scan your project on a set schedule and report all known vulnerabilities.

### Instructions

In your project repository, create a new file `.github/workflows/osv-scanner-scheduled.yml`.

Include the following in the [`osv-scanner-scheduled.yml`](https://github.com/google/osv-scanner/blob/main/.github/workflows/osv-scanner-scheduled.yml) file:

```yml
name: OSV-Scanner Scheduled Scan

on:
  schedule:
    - cron: '12 12 * * 1'
# Change "main" to your default branch if you use a different name, i.e. "master"
  push:
    branches: [ main ]

permissions:
  # Require writing security events to upload SARIF file to security tab
  security-events: write
  # Only need to read contents
  contents: read

jobs:
  scan-scheduled:
    uses: "google/osv-scanner/.github/workflows/osv-scanner-reusable.yml@main"
```

As written, the scanner will run on 12:12 pm UTC every Monday. You can change the schedule by following the instructions [here](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#schedule).

### Customization

`osv-scanner-reusable.yml` takes the `scan-args` parameter as input, this value is passed to `osv-scanner` CLI after being split by each line. See the [usage]()./usage) page for the available options.

Importantly `--format` and `--output` flags are already set by the reusable workflow and should not be overridden here.

#### Examples
```yml
# Scan specific lockfiles
jobs:
  scan-pr:
    uses: "./.github/workflows/osv-scanner-reusable.yml"
    with:
      scan-args: |-
        ./path/to/lockfile1
        ./path/to/lockfile2
```

```yml
# Default arguments
jobs:
  scan-pr:
    uses: "./.github/workflows/osv-scanner-reusable.yml"
    with:
      scan-args: |-
        --recursive
        --skip-git=true
        ./
```

### View results

Maintainers can review results of the scan by navigating to their project's `security > code scanning` tab. Vulnerability details can also be viewed by clicking on the details of the failed action.

## Scans on PRs

Scanning your project on each pull request can help you keep vulnerabilities out of your project. This GitHub Action compares a vulnerability scan of the main branch to a vulnerability scan of the feature branch. You will be notified of any new vulnerabilities introduced through the feature branch. You can also choose to [prevent merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging) if new vulnerabilities are introduced through the feature branch.

### Instructions

In your project repository, create a new file `.github/workflows/osv-scanner-pr.yml`.

Include the following in the [`osv-scanner-pr.yml`](https://github.com/google/osv-scanner/blob/main/.github/workflows/osv-scanner-pr.yml) file:

```yml
name: OSV-Scanner PR Scan

# Change "main" to your default branch if you use a different name, i.e. "master"
on:
  pull_request:
    branches: [ main ]
  merge_group:
    branches: [ main ]

# Declare default permissions as read only.
permissions: read-all

jobs:
  scan-pr:
    uses: "google/osv-scanner/.github/workflows/osv-scanner-reusable-pr.yml@main"
```

### View results

Results may be viewed by clicking on the details of the failed action, either from your project's actions tab or directly on the PR. Results are also included in GitHub annotations on the "Files changed" tab for the PR.

### Customization

`osv-scanner-reusable-pr.yml` has the same customization options as `osv-scanner-reusable.yml`, which is described [here](./github-action.md#customization).

## Scan on release

Here is a example of blocking on release, though the actual implementation will heavily depend on your specific release process.

```yml
name: Go Release Process

on:
  push:
    tags:
      - "*" # triggers only if push new tag version, like `0.8.4` or else

permissions:
  contents: read # to fetch code (actions/checkout)

jobs:
  osv-scan:
    uses: ./.github/workflows/osv-scanner-reusable.yml
    with:
      # Only scan the top level go.mod file without recursively scanning directories since
      # this is pipeline is about releasing the go module and binary
      scan-args: |-
        --skip-git
        ./
    permissions:
      # Require writing security events to upload SARIF file to security tab
      security-events: write
  tests:
    name: Run unit tests
    ...
  release:
    needs: # Needs both tests and osv-scan to pass
      - tests
      - osv-scan
    # Your actual release steps
    steps:
      ...
```

### View results

Results may be viewed by clicking on the details of the failed release action from the action tab.
