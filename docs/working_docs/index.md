---
layout: default
title: Working
has_children: true
nav_order: 7
nav_exclude: true
permalink: /working/
---

{% include warning.html %}

# OSV-Scanner

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner)

Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies.

OSV-Scanner provides an officially supported frontend to the [OSV database](https://osv.dev/) that connects a project’s list of dependencies with the vulnerabilities that affect them. Since the OSV.dev database is open source and distributed, it has several benefits in comparison with closed source advisory databases and scanners:

- Each advisory comes from an open and authoritative source (e.g. the [RustSec Advisory Database](https://github.com/rustsec/advisory-db))
- Anyone can suggest improvements to advisories, resulting in a very high quality database
- The OSV format unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer’s list of packages

The above all results in fewer, more actionable vulnerability notifications, which reduces the time needed to resolve them. Check out our [announcement blog post] for more details!

[announcement blog post]: https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html