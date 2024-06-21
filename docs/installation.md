---
layout: page
title: Installation
permalink: /installation/
nav_order: 3
---

# Installation

You may download the [SLSA3](https://slsa.dev) compliant binaries for Linux, macOS, and Windows from our [releases page](https://github.com/google/osv-scanner/releases).

## Package Managers

[![Packaging status](https://repology.org/badge/vertical-allrepos/osv-scanner.svg)](https://repology.org/project/osv-scanner/versions)

### Windows Scoop

[Windows Scoop](https://scoop.sh) users can install osv-scanner from the [official bucket](https://github.com/ScoopInstaller/Main/blob/master/bucket/osv-scanner.json):

```bash
scoop install osv-scanner
```

### Homebrew

[Homebrew](https://brew.sh/) users can install [osv-scanner](https://formulae.brew.sh/formula/osv-scanner) via:

```bash
brew install osv-scanner
```

### Arch Linux

Arch Linux users can install osv-scanner from the official repo:

```bash
pacman -S osv-scanner
```

### Alpine Linux

Alpine Linux users can install osv-scanner from the official repo:

```bash
apk add osv-scanner
```

### FreeBSD

FreeBSD users can install osv-scanner from the official repo:

```bash
pkg install osv-scanner
```

### NetBSD

NetBSD users can install osv-scanner from the official repo:

```bash
pkg_add osv-scanner
```

### OpenBSD

OpenBSD users can install osv-scanner from the official repo:

```bash
pkg_add osv-scanner
```

## Install from source

Alternatively, you can install this from source by running:

```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

This requires Go 1.21.11+ to be installed.

## Build from source

See our [contribution guidelines](https://github.com/google/osv-scanner/blob/main/CONTRIBUTING.md) for instructions on how to build from source.

## Verifying Builds

Each of our releases come with SLSA provenance data (`multiple.intoto.jsonl`),
which can be used to verify the source and provenance of the binaries with the [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) tool.

E.g.

```bash
slsa-verifier verify-artifact ./osv-scanner_1.2.0_linux_amd64 --provenance-path multiple.intoto2.jsonl --source-uri github.com/google/osv-scanner --source-tag v1.2.0
```

## SemVer Adherence

All releases on the same Major version will be guaranteed to have backward compatible JSON output and CLI arguments.
However, features prefixed with `experimental` (e.g. `--experimental-call-analysis`) might be changed or removed with only a Minor version change.
