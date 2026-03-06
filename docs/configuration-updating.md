---
layout: page
permalink: /experimental/configuration-updating/
parent: Experimental Features
nav_order: 6
---

# Configuration updating

Experimental
{: .label }

{: .no_toc }

OSV-Scanner can automatically update ignored vulnerabilities in `osv-scanner.toml` files, either to remove unused ignore entries, or to ignore all found vulnerabilities.

This requires that a configuration file already exists, and currently makes no attempt to preserve comments or syntax.

## Usage

```
# remove only ignore entires that are not being used
osv-scanner scan --experimental-update-config-ignores=unused .

# add ignore entries for all found vulnerabilities
osv-scanner scan --experimental-update-config-ignores=all .
```
