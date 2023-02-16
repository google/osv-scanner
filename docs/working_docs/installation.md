---
layout: default
title: Installation
nav_order: 1
nav_exclude: true
parent: Working
permalink: /working/installation
---
{% include warning.html %}

## Installing

You may download the [SLSA3](https://slsa.dev) compliant binaries for Linux, macOS, and Windows from our [releases page](https://github.com/google/osv-scanner/releases).

### Package Managers

[![Packaging status](https://repology.org/badge/vertical-allrepos/osv-scanner.svg)](https://repology.org/project/osv-scanner/versions)

If you're a [**Windows Scoop**](https://scoop.sh) user, then you can install osv-scanner from the [official bucket](https://github.com/ScoopInstaller/Main/blob/master/bucket/osv-scanner.json):

```bash
scoop install osv-scanner
```

If you're a [Homebrew](https://brew.sh/) user, you can install [osv-scanner](https://formulae.brew.sh/formula/osv-scanner) via:

```bash
brew install osv-scanner
```

If you're a Arch Linux User, you can install osv-scanner from the official repo:
```bash
pacman -S osv-scanner
```

### Install from source

Alternatively, you can install this from source by running:

```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

This requires Go 1.18+ to be installed.

### Build from source

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

### SemVer Adherence

All releases on the same Major version will be guaranteed to have backward compatible JSON output and CLI arguments.
