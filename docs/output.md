---
layout: page
title: Output
permalink: /output/
nav_order: 5
---
# Output
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Explanation of output data

For every vulnerability found, OSV-Scanner will display the following information:

- OSV URL: Link to the database entry for the vulnerability
- CVSS: CVSS v2 or v3, calculated from the [severity[].score](https://ossf.github.io/osv-schema/#severity-field) field.
- Ecosystem: Ecosystem associated with the package
- Package: Package name
- Version: Package version
- Source: Path to the sbom or lockfile where the package originated

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
╭─────────────────────────────────────┬──────┬───────────┬──────────────────────────┬─────────┬────────────────────╮
│ OSV URL                             │ CVSS │ ECOSYSTEM │  PACKAGE                 │ VERSION │ SOURCE             │
├─────────────────────────────────────┼──────┼───────────┼──────────────────────────┼─────────┼────────────────────┤
│ https://osv.dev/GHSA-c3h9-896r-86jm | 8.6  │ Go        │ github.com/gogo/protobuf │ 1.3.1   │ path/to/go.mod     │
│ https://osv.dev/GHSA-m5pq-gvj9-9vr8 | 7.5  │ crates.io │ regex                    │ 1.3.1   │ path/to/Cargo.lock │
╰─────────────────────────────────────┴──────┴───────────┴──────────────────────────┴─────────┴────────────────────╯
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
| OSV URL | CVSS | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- | --- |
| https://osv.dev/GHSA-c3h9-896r-86jm<br/>https://osv.dev/GO-2021-0053 | 8.6 | Go | github.com/gogo/protobuf | 1.3.1 | ../scorecard-check-osv-e2e/go.mod |
| https://osv.dev/GHSA-m5pq-gvj9-9vr8<br/>https://osv.dev/RUSTSEC-2022-0013 | 7.5 | crates.io | regex | 1.5.1 | ../scorecard-check-osv-e2e/sub-rust-project/Cargo.lock |
```

**Rendered:**

| OSV URL | CVSS | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- | --- |
| https://osv.dev/GHSA-c3h9-896r-86jm<br/>https://osv.dev/GO-2021-0053 | 8.6 | Go | github.com/gogo/protobuf | 1.3.1 | ../scorecard-check-osv-e2e/go.mod |
| https://osv.dev/GHSA-m5pq-gvj9-9vr8<br/>https://osv.dev/RUSTSEC-2022-0013 | 7.5 | crates.io | regex | 1.5.1 | ../scorecard-check-osv-e2e/sub-rust-project/Cargo.lock |

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

## Return Codes

|----- 
| Exit Code |Reason| 
|:---------------:|------------| 
| `0` | Packages were found when scanning, but does not match any known vulnerabilities. | 
| `1` | Packages were found when scanning, and there are vulnerabilities. | 
| `1-126` | Reserved for vulnerability result related errors. | 
| `127` | General Error. | 
| `128` | No packages found (likely caused by the scanning format not picking up any files to scan). | 
| `129-255` | Reserved for non result related errors. | 
