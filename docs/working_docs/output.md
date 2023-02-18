---
layout: default
title: Output
nav_order: 4
nav_exclude: true
parent: Working
permalink: /working/output
---
{% include warning.html %}

## Output formats

You can control the format used by the scanner to output results with the `--format` flag. The different formats supported by the scanner are:

### `table` format

The default format, which outputs the results as a human-readable table.

Sample output:

```bash
╭─────────────────────────────────────┬───────────┬──────────────────────────┬─────────┬────────────────────╮
│ OSV URL (ID IN BOLD)                │ ECOSYSTEM │ PACKAGE                  │ VERSION │ SOURCE             │
├─────────────────────────────────────┼───────────┼──────────────────────────┼─────────┼────────────────────┤
│ https://osv.dev/GHSA-c3h9-896r-86jm │ Go        │ github.com/gogo/protobuf │ 1.3.1   │ path/to/go.mod     │
│ https://osv.dev/GHSA-m5pq-gvj9-9vr8 │ crates.io │ regex                    │ 1.3.1   │ path/to/Cargo.lock │
╰─────────────────────────────────────┴───────────┴──────────────────────────┴─────────┴────────────────────╯
```

### `json` format

Outputs the results as a JSON object to stdout, with all other output being directed to stderr - this makes it safe to redirect the output to a file with `osv-scanner --format json ... > /path/to/file.json`.

Sample output:

```json
{
  "results": [
    {
      "packageSource": {
        "path": "/absolute/path/to/go.mod",
        // One of: lockfile, sbom, git, docker
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "github.com/gogo/protobuf",
            "version": "1.3.1",
            "ecosystem": "Go"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-c3h9-896r-86jm",
              "aliases": [
                "CVE-2021-3121"
              ],
              // ... Full OSV
            },
            {
              "id": "GO-2021-0053",
              "aliases": [
                "CVE-2021-3121",
                "GHSA-c3h9-896r-86jm"
              ],
              // ... Full OSV
            }
          ],
          // Grouping based on aliases, if two vulnerability share the same alias, or alias each other,
          // they are considered the same vulnerability, and is grouped here under the id field.
          "groups": [
            {
              "ids": [
                "GHSA-c3h9-896r-86jm",
                "GO-2021-0053"
              ]
            }
          ]
        }
      ]
    },
    {
      "packageSource": {
        "path": "/absolute/path/to/Cargo.lock",
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "regex",
            "version": "1.5.1",
            "ecosystem": "crates.io"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-m5pq-gvj9-9vr8",
              "aliases": [
                "CVE-2022-24713"
              ],
              // ... Full OSV
            },
            {
              "id": "RUSTSEC-2022-0013",
              "aliases": [
                "CVE-2022-24713"
              ],
              // ... Full OSV
            }
          ],
          "groups": [
            {
              "ids": [
                "GHSA-m5pq-gvj9-9vr8",
                "RUSTSEC-2022-0013"
              ]
            }
          ]
        }
      ]
    }
  ]
}
```