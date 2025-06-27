---
layout: page
permalink: /experimental/osv-reporter/
parent: Experimental Features
nav_order: 4
---

# OSV-Reporter

Experimental
{: .label }

OSV-Reporter can be used to perform some experimental operations on the OSV-Scanner output JSON.

## Features

- Create a diff between two osv-scanner.json outputs, so you can see only new vulnerabilities.

```bash
$ osv-reporter --old previous-osv-scanner.json --new current-osv-scanner.json
```

- Output multiple different formats from a single set of scan results.

```bash
$ osv-reporter --new osv-scanner.json --output=[format]:[output-path],[format2]:[output-path2]
```

## How to install

We don't provide prebuilt binaries for osv-reporter as it is very experimental and can change at any point.

Currently you can install it from source via `go install`:
```bash
$ go install github.com/google/osv-scanner/v2/cmd/osv-reporter@latest
# Or @main for the latest commit
```
