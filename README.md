<picture>
    <source srcset="/docs/images/osv-scanner-full-logo-darkmode.svg"  media="(prefers-color-scheme: dark)">
    <!-- markdown-link-check-disable-next-line -->
    <img src="/docs/images/osv-scanner-full-logo-lightmode.svg">
</picture>

---

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/google/osv-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/osv-scanner)](https://goreportcard.com/report/github.com/google/osv-scanner)
[![codecov](https://codecov.io/gh/google/osv-scanner/graph/badge.svg?token=C8IDVX9LP5)](https://codecov.io/gh/google/osv-scanner)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![GitHub Release](https://img.shields.io/github/v/release/google/osv-scanner)](https://github.com/google/osv-scanner/releases)

Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies.
OSV-Scanner provides an officially supported frontend to the [OSV database](https://osv.dev/) and CLI interface to [OSV-Scalibr](https://github.com/google/osv-scalibr) that connects a project’s list of dependencies with the vulnerabilities that affect them.

OSV-Scanner supports a wide range of project types, package managers and features, including but not limited to:

- **Languages:** C/C++, Dart, Elixir, Go, Java, Javascript, PHP, Python, R, Ruby, Rust.
- **Package Managers:** npm, pip, yarn, maven, go modules, cargo, gem, composer, nuget and others.
- **Operating Systems:** Detects vulnerabilities in OS packages on Linux systems.
- **Containers:** Scans container images for vulnerabilities in their base images and included packages.
- **Guided Remediation:** Provides recommendations for package version upgrades based on criteria such as dependency depth, minimum severity, fix strategy, and return on investment.

OSV-Scanner uses the extensible [OSV-Scalibr](https://github.com/google/osv-scalibr) library under the hood to provide this functionality. If a language or package manager is not supported currently, please file a [feature request.](https://github.com/google/osv-scanner/issues)

#### Underlying database

The underlying database, [OSV.dev](https://osv.dev/) has several benefits in comparison with closed source advisory databases and scanners:

- Covering most open source language and OS ecosystems (including [Git](https://osv.dev/list?q=&ecosystem=GIT)), it’s comprehensive.
- Each advisory comes from an open and authoritative source (e.g. [GitHub Security Advisories](https://github.com/github/advisory-database), [RustSec Advisory Database](https://github.com/rustsec/advisory-db), [Ubuntu security notices](https://github.com/canonical/ubuntu-security-notices/tree/main/osv))
- Anyone can suggest improvements to advisories, resulting in a very high quality database.
- The OSV format unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer’s list of packages

The above all results in accurate and actionable vulnerability notifications, which reduces the time needed to resolve them. Check out [OSV.dev](https://osv.dev/) for more details!

## Basic installation

To install OSV-Scanner, please refer to the [installation section](https://google.github.io/osv-scanner/installation) of our documentation. OSV-Scanner releases can be found on the [releases page](https://github.com/google/osv-scanner/releases) of the GitHub repository. The recommended method is to download a prebuilt binary for your platform. Alternatively, you can use
`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` to build it from source.

## Key Features

For more information, please read our [detailed documentation](https://google.github.io/osv-scanner) to learn how to use OSV-Scanner. For detailed information about each feature, click their titles in this README.

Please note: These are the instructions for the latest OSV-Scanner V2 beta. If you are using V1, checkout the V1 [README](https://github.com/google/osv-scanner-v1) and [documentation](https://google.github.io/osv-scanner-v1/) instead.

### [Scanning a source directory](https://google.github.io/osv-scanner/usage)

```bash
$ osv-scanner scan source -r /path/to/your/dir
```

This command will recursively scan the specified directory for any supported package files, such as `package.json`, `go.mod`, `pom.xml`, etc. and output any discovered vulnerabilities.

OSV-Scanner has the option of using call analysis to determine if a vulnerable function is actually being used in the project, resulting in fewer false positives, and actionable alerts.

OSV-Scanner can also detect vendored C/C++ code for vulnerability scanning. See [here](https://google.github.io/osv-scanner/usage/#cc-scanning) for details.

#### Supported Lockfiles

OSV-Scanner supports 11+ language ecosystems and 19+ lockfile types. To check if your ecosystem is covered, please check out our [detailed documentation](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/#supported-lockfiles).

### [Container Scanning](https://google.github.io/osv-scanner/usage/scan-image)

OSV-Scanner also supports comprehensive, layer-aware scanning for container images to detect vulnerabilities the following operating system packages and language-specific dependencies.

| Distro Support | Language Artifacts Support |
| -------------- | -------------------------- |
| Alpine OS      | Go                         |
| Debian         | Java                       |
| Ubuntu         | Node                       |
|                | Python                     |

See the [full documentation](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/#supported-artifacts) for details on support.

**Usage**:

```bash
$ osv-scanner scan image my-image-name:tag
```

![screencast of html output of container scanning](https://github.com/user-attachments/assets/8bb95366-27ec-45d1-86ed-e42890f2fb46)

### [License Scanning](https://google.github.io/osv-scanner/usage/license-scanning/)

Check your dependencies' licenses using deps.dev data. For a summary:

```bash
osv-scanner --licenses path/to/repository
```

To check against an allowed license list (SPDX format):

```bash
osv-scanner --licenses="MIT,Apache-2.0" path/to/directory
```

### [Offline Scanning](https://google.github.io/osv-scanner/usage/offline-mode/)

Scan your project against a local OSV database. No network connection is required after the initial database download. The database can also be manually downloaded.

```bash
osv-scanner --offline --download-offline-databases ./path/to/your/dir
```

### [Guided Remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/) (Experimental)

OSV-Scanner provides guided remediation, a feature that suggests package version upgrades based on criteria such as dependency depth, minimum severity, fix strategy, and return on investment.
We currently support remediating vulnerabilities in the following files:

| Ecosystem | File Format (Type)             | Supported Remediation Strategies                                                                                  |
| :-------- | :----------------------------- | :---------------------------------------------------------------------------------------------------------------- |
| npm       | `package-lock.json` (lockfile) | [`in-place`](https://google.github.io/osv-scanner/experimental/guided-remediation/#in-place-lockfile-remediation) |
| npm       | `package.json` (manifest)      | [`relock`](https://google.github.io/osv-scanner/experimental/guided-remediation/#in-place-lockfile-remediation)   |
| Maven     | `pom.xml` (manifest)           | [`override`](https://google.github.io/osv-scanner/experimental/guided-remediation/#override-dependency-versions)  |

This is available as a headless CLI command, as well as an interactive mode.

#### Example (for npm)

```bash
$ osv-scanner fix \
    --max-depth=3 \
    --min-severity=5 \
    --ignore-dev  \
    --strategy=in-place \
    -L path/to/package-lock.json
```

#### Interactive mode (for npm)

```bash
$ osv-scanner fix \
    -M path/to/package.json \
    -L path/to/package-lock.json
```

<img src="https://google.github.io/osv-scanner/images/guided-remediation-relock-patches.png" alt="Screenshot of the interactive relock results screen with some relaxation patches selected">

## Contribute

### Report Problems

If you have what looks like a bug, please use the [GitHub issue tracking system](https://github.com/google/osv-scanner/issues). Before you file an issue, please search existing issues to see if your issue is already covered.

### Contributing code to `osv-scanner`

See [CONTRIBUTING.md](CONTRIBUTING.md) for documentation on how to contribute code.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=google/osv-scanner&type=Date)](https://star-history.com/#google/osv-scanner&Date)
