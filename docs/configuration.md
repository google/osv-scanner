---
layout: page
title: Configuration
permalink: /configuration/
nav_order: 5
---

# Configure OSV-Scanner

To configure scanning, place an osv-scanner.toml file in the scanned file's directory. To override this osv-scanner.toml file, pass the `--config=/path/to/config.toml` flag with the path to the configuration you want to apply instead.

## Ignore vulnerabilities by ID

To ignore a vulnerability, enter the ID under the `IgnoreVulns` key. Optionally, add an expiry date or reason.

### Example

```toml
[[IgnoredVulns]]
id = "GO-2022-0968"
# ignoreUntil = 2022-11-09 # Optional exception expiry date
reason = "No ssh servers are connected to or hosted in Go lang"

[[IgnoredVulns]]
id = "GO-2022-1059"
# ignoreUntil = 2022-11-09 # Optional exception expiry date
reason = "No external http servers are written in Go lang."
```

Ignoring a vulnerability will also ignore vulnerabilities that are considered aliases of that vulnerability.

## Override specific package

To ignore a specific a package, or manually set its license, enter the package name and ecosystem under the `PackageOverrides` key.

```toml
[[PackageOverrides]]
# The package name, version, and ecosystem to match against
name = "lib"
# If version is not set or empty, it will match every version
version = "1.0.0"
ecosystem = "Go"
# Ignore this package entirely, including license scanning
ignore = true
# Override the license of the package
# This is not used if ignore = true
license.override = ["MIT", "0BSD"]
# effectiveUntil = 2022-11-09 # Optional exception expiry date
reason = "abc"
```
