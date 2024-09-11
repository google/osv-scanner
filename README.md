# OSV-Scanner

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/google/osv-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/osv-scanner)](https://goreportcard.com/report/github.com/google/osv-scanner)
[![codecov](https://codecov.io/gh/google/osv-scanner/graph/badge.svg?token=C8IDVX9LP5)](https://codecov.io/gh/google/osv-scanner)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![GitHub Release](https://img.shields.io/github/v/release/google/osv-scanner)](https://github.com/google/osv-scanner/releases)

Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies.

OSV-Scanner provides an officially supported frontend to the [OSV database](https://osv.dev/) that connects a project’s list of dependencies with the vulnerabilities that affect them. Since the OSV.dev database is open source and distributed, it has several benefits in comparison with closed source advisory databases and scanners:

- Each advisory comes from an open and authoritative source (e.g. the [RustSec Advisory Database](https://github.com/rustsec/advisory-db))
- Anyone can suggest improvements to advisories, resulting in a very high quality database
- The OSV format unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer’s list of packages

The above all results in fewer, more actionable vulnerability notifications, which reduces the time needed to resolve them. Check out our [announcement blog post] for more details!

[announcement blog post]: https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html

## Documentation

Read our [detailed documentation](https://google.github.io/osv-scanner) to learn how to use OSV-Scanner.

## Go toolchain compatibility policy

We aim to keep the osv-scanner library packages compatible with supported versions of Go (last 2 Go releases), while always building osv-scanner binaries with the latest version of Go.

## Contribute

### Report Problems

If you have what looks like a bug, please use the [GitHub issue tracking system](https://github.com/google/osv-scanner/issues). Before you file an issue, please search existing issues to see if your issue is already covered.

### Contributing code to `osv-scanner`

See [CONTRIBUTING.md](CONTRIBUTING.md) for documentation on how to contribute code.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=google/osv-scanner&type=Date)](https://star-history.com/#google/osv-scanner&Date)
