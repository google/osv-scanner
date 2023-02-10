---
layout: default
title: Configuration
nav_order: 3
#nav_exclude: true
parent: Working
permalink: /working/configuration
---
{: .warning }
These docs are a work in progress! You are welcome to browse, but you may find features/options that are not compatible with the currently released version of OSV-Scanner. Current OSV-Scanner configuration docs can be found [here](../configuration). 

## Configure OSV-Scanner

To configure scanning, place an osv-scanner.toml file in the scanned file's directory. To override this osv-scanner.toml file, pass the `--config=/path/to/config.toml` flag with the path to the configuration you want to apply instead.

Currently, there is only 1 option to configure:

### Ignore vulnerabilities by ID

To ignore a vulnerability, enter the ID under the `IgnoreVulns` key. Optionally, add an expiry date or reason.

#### Example

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