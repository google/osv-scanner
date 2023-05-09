---
layout: page
title: Output
permalink: /output/
nav_order: 5
---
## Output formats

You can control the format used by the scanner to output results with the `--format` flag.

### Table (Default)

The default format, which outputs the results as a human-readable table.

```bash
osv-scanner --format table your/project/dir
```

<details markdown="1">
<summary><b>Sample table output</b></summary>

```bash
╭─────────────────────────────────────┬───────────┬──────────────────────────┬─────────┬────────────────────╮
│ OSV URL (ID IN BOLD)                │ ECOSYSTEM │ PACKAGE                  │ VERSION │ SOURCE             │
├─────────────────────────────────────┼───────────┼──────────────────────────┼─────────┼────────────────────┤
│ https://osv.dev/GHSA-c3h9-896r-86jm │ Go        │ github.com/gogo/protobuf │ 1.3.1   │ path/to/go.mod     │
│ https://osv.dev/GHSA-m5pq-gvj9-9vr8 │ crates.io │ regex                    │ 1.3.1   │ path/to/Cargo.lock │
╰─────────────────────────────────────┴───────────┴──────────────────────────┴─────────┴────────────────────╯
```
</details>

---

### Markdown Table

```bash
osv-scanner --format markdown your/project/dir
```

<details markdown="1">
<summary><b>Sample markdown output</b></summary>

**Raw output:**

```
| OSV URL | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- |
| https://osv.dev/GHSA-c3h9-896r-86jm<br/>https://osv.dev/GO-2021-0053 | Go | github.com/gogo/protobuf | 1.3.1 | ../scorecard-check-osv-e2e/go.mod |
| https://osv.dev/GHSA-m5pq-gvj9-9vr8<br/>https://osv.dev/RUSTSEC-2022-0013 | crates.io | regex | 1.5.1 | ../scorecard-check-osv-e2e/sub-rust-project/Cargo.lock |
```

**Rendered:**

| OSV URL | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- |
| https://osv.dev/GHSA-c3h9-896r-86jm<br/>https://osv.dev/GO-2021-0053 | Go | github.com/gogo/protobuf | 1.3.1 | ../scorecard-check-osv-e2e/go.mod |
| https://osv.dev/GHSA-m5pq-gvj9-9vr8<br/>https://osv.dev/RUSTSEC-2022-0013 | crates.io | regex | 1.5.1 | ../scorecard-check-osv-e2e/sub-rust-project/Cargo.lock |

</details>

---

### JSON

```bash
osv-scanner --format json your/project/dir
```

Outputs the results as a JSON object to stdout, with all other output being directed to stderr - this makes it safe to redirect the output to a file with
```bash
osv-scanner --format json -L path/to/lockfile > /path/to/file.json
```

<details markdown="1">
<summary><b>Sample JSON output</b></summary>

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
              ],
              // Call stack analysis is done using the `--experimental-call-analysis` flag
              // and result is matched against data provided by the advisory to check if
              // affected code is actually being executed.
              "experimentalAnalysis": {
                "GO-2021-0053": {
                  "called": false
                }
              }
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

</details>