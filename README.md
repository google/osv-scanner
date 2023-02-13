# OSV-Scanner

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner)

Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies.

OSV-Scanner provides an officially supported frontend to the [OSV database](https://osv.dev/) that connects a project’s list of dependencies with the vulnerabilities that affect them. Since the OSV.dev database is open source and distributed, it has several benefits in comparison with closed source advisory databases and scanners:

- Each advisory comes from an open and authoritative source (e.g. the [RustSec Advisory Database](https://github.com/rustsec/advisory-db))
- Anyone can suggest improvements to advisories, resulting in a very high quality database
- The OSV format unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer’s list of packages

The above all results in fewer, more actionable vulnerability notifications, which reduces the time needed to resolve them. Check out our [announcement blog post] for more details!

[announcement blog post]: https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html

## Table of Contents

- [OSV-Scanner](#osv-scanner)
  - [Table of Contents](#table-of-contents)
  - [Installing](#installing)
    - [Package Managers](#package-managers)
    - [Install from source](#install-from-source)
    - [Build from source](#build-from-source)
    - [SemVer Adherence](#semver-adherence)
  - [Usage](#usage)
  - [Contribute](#contribute)
    - [Report Problems](#report-problems)
    - [Contributing code to `osv-scanner`](#contributing-code-to-osv-scanner)
  - [Stargazers over time](#stargazers-over-time)

## Installing

You may download the [SLSA3](https://slsa.dev) compliant binaries for Linux, macOS, and Windows from our [releases page](https://github.com/google/osv-scanner/releases).

### Package Managers

[![Packaging status](https://repology.org/badge/vertical-allrepos/osv-scanner.svg)](https://repology.org/project/osv-scanner/versions)

If you're a [**Windows Scoop**](https://scoop.sh) user, then you can install osv-scanner from the [official bucket](https://github.com/ScoopInstaller/Main/blob/master/bucket/osv-scanner.json):

```console
scoop install osv-scanner
```

If you're a [Homebrew](https://brew.sh/) user, you can install [osv-scanner](https://formulae.brew.sh/formula/osv-scanner) via:

```console
brew install osv-scanner
```

If you're a Arch Linux User, you can install osv-scanner from the official repo:
```
pacman -S osv-scanner
```

### Install from source

Alternatively, you can install this from source by running:

```console
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

This requires Go 1.18+ to be installed.

### Build from source

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

### SemVer Adherence

All releases on the same Major version will be guaranteed to have backward compatible JSON output and CLI arguments.

## Usage

OSV-Scanner parses lockfiles, SBOMs, and git directories to determine your project's open source dependencies. These dependencies are matched against the OSV database via the [OSV.dev API](https://osv.dev#use-the-api) and known vulnerabilities are returned to you in the output.

See the current stable release [README.md](https://github.com/google/osv-scanner/blob/last-stable/README.md) for details on how to use and configure OSV-Scanner, and what output to expect. To see latest main branch usage, see [USAGE.md](./USAGE.md).

## Contribute

### Report Problems
If you have what looks like a bug, please use the [Github issue tracking system](https://github.com/google/osv-scanner/issues). Before you file an issue, please search existing issues to see if your issue is already covered.

### Contributing code to `osv-scanner`

See [CONTRIBUTING.md](CONTRIBUTING.md) for documentation on how to contribute code.


## Stargazers over time

[![Stargazers over time](https://starchart.cc/google/osv-scanner.svg)](https://starchart.cc/google/osv-scanner)
