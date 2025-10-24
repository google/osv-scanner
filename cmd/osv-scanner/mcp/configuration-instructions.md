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
