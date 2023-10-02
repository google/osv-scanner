---
layout: page
title: GitHub Action
permalink: /github-action/
nav_order: 6
---

# GitHub Action

{: .no_toc }

OSV-Scanner is offered as a GitHub Action. We currently have two different GitHub Actions:

1. An action that performs a vulnerability scan on a [regular schedule](./github-action.md#scheduled-scans).
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

### View results

Maintainers can review results of the scan by navigating to their project's security > code scanning tab. Vulnerability details can also be viewed by clicking on the details of the failed action.

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

Results are also available to maintainers by navigating to their project's security > code scanning tab.
