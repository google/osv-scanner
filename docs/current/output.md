---
layout: page
title: Output
permalink: /output/
nav_order: 5
---
## JSON output
By default osv-scanner outputs a human readable table. To have osv-scanner output JSON instead, pass the `--json` flag when calling osv-scanner.

When using the --json flag, only the JSON output will be printed to stdout, with all other outputs being directed to stderr. So to save only the json output to file, you can redirect the output with `osv-scanner --json ... > /path/to/file.json`

### Output Format

~~~~~~~~~~~~~~~~~~~
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
~~~~~~~~~~~~~~~~~~~