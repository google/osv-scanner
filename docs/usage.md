---
layout: page
title: Usage
permalink: /usage/
nav_order: 4
---

# Usage Guide

{: .note }
This documentation is for the beta V2 release. For the older, V1 release documentation, check out <https://google.github.io/osv-scanner-v1>.

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Core Concept

OSV-Scanner operates in a two-step process:

1. **Package Extraction**: The tool first extracts information about the packages used in your project, container image, or other target.

2. **Vulnerability Matching**: The extracted package information is then matched against known vulnerability databases to identify potential security issues.

## Subcommands

OSV-Scanner V2 is divided into several subcommands:

| Subcommand    | Documentation Link                                   | Quick Example                                                          |
| ------------- | ---------------------------------------------------- | ---------------------------------------------------------------------- |
| `scan`        | [Further down this page](./usage.md#scan-subcommand) | `osv-scanner scan -r ./my-project-dir/`                                |
| `scan source` | [Source Project Scanning]()                          | Source scanning is default, so the example is the same as above.       |
| `scan image`  | [Container Scanning](./container-image-scanning.md)  | `osv-scanner scan image my-docker-img:latest`                          |
| `fix`         | [Guided Remediation](./guided-remediation.md)        | `osv-scanner fix -M path/to/package.json -L path/to/package-lock.json` |

### The `scan` Subcommand

The `scan` subcommand is the primary way to initiate vulnerability scans. It has two subcommands of its own: `source` (default) and `image`.

- **`scan source`**: Scans source code directories for package dependencies and vulnerabilities. See the [Scanning Source documentation](./scan-source.md) for more details.

- **`scan image`**: Scans container images for vulnerabilities. See the [Scanning Container Images documentation](./scan-image.md) for more details.

Both `scan source` and `scan image` share a common set of flags for configuring the scan and output.

## Post-Extraction Flags:

### Saving to File

The `--output` flag can be used to save the scan results to a file instead of being printed on the stdout:

```bash
osv-scanner scan -L package-lock.json --output scan-results.txt
```

### Setting Output Format

The `--format` flag can be used to specify the output format osv-scanner gives.

See [Output](./output.md) page for more details.

```bash
osv-scanner scan -L package-lock.json --format json
```

### Override config file

The `--config` flag can be used to specify a global config override to apply to all of the files you are scanning.

See [Config](./configuration.md) for more details.

```bash
osv-scanner scan -L package-lock.json --config ./my-osv-scanner-config.toml
```

### Set verbosity level

The `--verbosity` flag can be used to set the verbosity level. See `--help` output for possible levels.

```bash
osv-scanner scan -L package-lock.json --verbosity info
```

### Serve HTML report locally

The `--serve` flag is a helper flag to set the output format to HTML, and serve the report locally on port 8000.

```bash
osv-scanner scan -L package-lock.json --serve
```

### Experimental features

Several experimental features are available through flags. See their respective documentation pages for more details:

- [`--experimental-offline-vulnerabilities`](./offline-mode.md)
- [`--experimental-licenses`](./license-scanning.md)
- `--experimental-no-resolve`: Disables transitive dependency resolution.
- `experimental-all-packages`: Outputs all packages in JSON format (make sure to set `--format=json`).

## Pre-Commit Integration

OSV-Scanner can be integrated as a [pre-commit](https://pre-commit.com) hook in your project.

1.  Add the `osv-scanner` hook to your `.pre-commit-config.yaml` file.

2.  Use the `args` key to pass command-line arguments as you would when running OSV-Scanner directly.

### Example

```yaml
repos:
  - repo: https://github.com/google/osv-scanner/
    rev: # pass a Git tag or commit hash here
    hooks:
      - id: osv-scanner
        args: ["-r", "/path/to/your/dir"]
```

## Running in a Docker Container

The OSV-Scanner Docker image can be pulled from the GitHub Container Registry:

```bash
docker pull ghcr.io/google/osv-scanner:latest
```

Once you have the image, you can test that it works by running:

```bash
docker run -it ghcr.io/google/osv-scanner -h
```

To run a scan, mount the directory to scan to `/src` and pass the necessary flags:

```bash
docker run -it -v ${PWD}:/src ghcr.io/google/osv-scanner -L /src/go.mod
```
