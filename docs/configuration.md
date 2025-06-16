---
layout: page
permalink: /configuration/
nav_order: 5
---

# Configuration

To configure scanning, place an osv-scanner.toml file in the scanned file's directory. This does not propagate to child directories.

**Example:**

```
/Cargo.lock
/osv-scanner.toml (1)
/child-dir/go.mod
/child-dir/osv-scanner.toml (2)
/child-dir/nested-dir/package-lock.json
```

`osv-scanner.toml (1)` will only apply to `Cargo.lock`, `osv-scanner.toml (2)` will only apply to `go.mod`, and no config will apply to `package-lock.json`.

To override `osv-scanner.toml` files, pass the `--config=/path/to/config.toml` flag with the path to the configuration you want to apply instead, this will apply `config.toml` to all files parsed, and ignore `osv-scanner.toml` in all directories.

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

## Override packages

You can specify overrides for particular packages to have them either ignored entirely or to set their license using the `PackageOverrides` key:

```toml
[[PackageOverrides]]
# One or more fields to match each package against:
name = "lib"
version = "1.0.0"
ecosystem = "Go"
group = "dev"

# Actions to take for matching packages:
ignore = true # Ignore this package completely, including both reporting vulnerabilities and license violations
vulnerability.ignore = true # Ignore vulnerabilities for this package, while still checking the license (if not also ignored)
license.ignore = true # Ignore the license of the package, while still checking for vulnerabilities (if not also ignored)
license.override = ["MIT", "0BSD"] # Override the license of the package, if it is not ignored from license scanning completely

effectiveUntil = 2022-11-09 # Optional exception expiry date, after which the override will no longer apply
reason = "abc" # Optional reason for the override, to explain why it was added
```

Overrides are applied if all the configured fields match, enabling you to create very broad or very specific overrides based on your needs:

```toml
# ignore everything in the current directory
[[PackageOverrides]]
ignore = true

# ignore a particular group
[[PackageOverrides]]
group = "dev"
ignore = true

# ignore a particular ecosystem
[[PackageOverrides]]
ecosystem = "go"
ignore = true

# ignore packages named "axios" regardless of ecosystem or group
[[PackageOverrides]]
name = "axios"
ignore = true

# ignore packages named "axios" in the npm ecosystem that are in the dev group
[[PackageOverrides]]
name = "axios"
ecosystem = "npm"
group = "dev"
ignore = true

# ... and so on
```
