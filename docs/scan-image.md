---
layout: page
parent: Usage
permalink: /usage/scan-image
nav_order: 1
---

# Container Image Scanning

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

OSV-Scanner analyzes container images by extracting package information and matching it against known vulnerabilities in the OSV.dev database. This helps identify potential security risks in your containerized applications.

### Prerequisites

- **Docker (Optional)**: If you want to scan images directly by name (e.g., my-image:latest) without exporting them first, the docker command-line tool must be installed and available in your system's PATH. If you choose to scan exported image archives, Docker is not required.

All image scanning is done with the `scan image` subcommand:

```bash
osv-scanner scan image <image-name>:<tag>
```

## Scanning Methods

You can scan container images using two primary methods:

1. **Direct Image Scan:** Specify the image name and tag (e.g., `my-image:latest`). OSV-Scanner will attempt to locate the image locally. If not found locally, it will attempt to pull the image from the appropriate registry using the `docker` command.

   ```bash
   osv-scanner scan image image-name:tag
   ```

   - **How it works:** OSV-Scanner uses `docker save` to export the image to a temporary archive, which is then analyzed. No container code is executed during the scan.

2. **Scan from Exported Image Archive:** If you have already exported your container image as a Docker archive (`.tar` file), you can scan it directly using the `--archive` flag. This method does not require Docker to be installed.

   ```bash
   osv-scanner scan image --archive ./path/to/my-image.tar
   ```

   - **How to create an image archive:** You can create an image archive using the following commands:

     ```bash
     # Using Docker
     docker save my-image:latest > my-image.tar

     # Using Podman
     podman save --format=docker-archive my-image:latest > my-image.tar

     # Other image tools: Use the docker archive format to export the tar
     ```

### Usage Notes

- **No other scan targets:** When using `scan image`, you cannot specify other scan targets (e.g., directories or lockfiles).

- **Configuration Flags:** All the global configuration flags available for the `scan` command (as described in the [Usage documentation](./usage.md)) can be used with the `scan image` subcommand. This includes flags for output format, verbosity, config files, and experimental features.

## Scanning targets

OSV-Scanner scans for OS packages and build artifacts, including dependency information, on the given image, and attributes them to specific layers in the container.

See [Supported Artifacts](./supported_languages_and_lockfiles.md#supported-artifacts) for details on what targets are scanned.

## Output

By default, OSV-Scanner provides a summarized output of the scan results, grouping vulnerabilities by package. This is designed to handle the large number of vulnerabilities often found in container images.

<details markdown="1">
<summary><b>Sample table output</b></summary>

```bash
Container Scanning Result (Debian GNU/Linux 12 (bookworm)):
Total 20 packages affected by 105 vulnerabilities (7 Critical, 14 High, 19 Medium, 1 Low, 64 Unknown) from 2 ecosystems.
54 vulnerabilities have fixes available.

Go
╭─────────────────────────────────────────────────────────────────────────────────────────────╮
│ Source:artifact:artifact/tester-built-with-1-21-0                                           │
├─────────┬───────────────────┬───────────────┬────────────┬──────────────────┬───────────────┤
│ PACKAGE │ INSTALLED VERSION │ FIX AVAILABLE │ VULN COUNT │ INTRODUCED LAYER │ IN BASE IMAGE │
├─────────┼───────────────────┼───────────────┼────────────┼──────────────────┼───────────────┤
│ stdlib  │ 1.21.0            │ Fix Available │         20 │ # 8 Layer        │ --            │
╰─────────┴───────────────────┴───────────────┴────────────┴──────────────────┴───────────────╯
╭─────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Source:artifact:src/tester                                                                                      │
├─────────────────────────────┬───────────────────┬───────────────┬────────────┬──────────────────┬───────────────┤
│ PACKAGE                     │ INSTALLED VERSION │ FIX AVAILABLE │ VULN COUNT │ INTRODUCED LAYER │ IN BASE IMAGE │
├─────────────────────────────┼───────────────────┼───────────────┼────────────┼──────────────────┼───────────────┤
│ github.com/gogo/protobuf    │ 1.3.1             │ Fix Available │          1 │ # 9 Layer        │ --            │
│ github.com/ipfs/go-bitfield │ 1.0.0             │ Fix Available │          1 │ # 9 Layer        │ --            │
│ stdlib                      │ 1.19.8            │ Fix Available │         25 │ # 9 Layer        │ --            │
╰─────────────────────────────┴───────────────────┴───────────────┴────────────┴──────────────────┴───────────────╯
Debian:12
╭───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Source:os:var/lib/dpkg/status                                                                             │
├─────────────┬───────────────────┬─────────────────────────┬────────────┬──────────────────┬───────────────┤
│ PACKAGE     │ INSTALLED VERSION │ FIX AVAILABLE           │ VULN COUNT │ INTRODUCED LAYER │ IN BASE IMAGE │
├─────────────┼───────────────────┼─────────────────────────┼────────────┼──────────────────┼───────────────┤
│ aom         │ 3.6.0-1+deb12u1   │ No fix available        │          2 │ # 1 Layer        │ --            │
...
│ zlib        │ 1:1.2.13.dfsg-1   │ No fix available        │          1 │ # 0 Layer        │ debian        │
╰─────────────┴───────────────────┴─────────────────────────┴────────────┴──────────────────┴───────────────╯

Filtered Vulnerabilities:
╭─────────────┬───────────┬───────────────────────┬─────────────────────┬────────────────╮
│ PACKAGE     │ ECOSYSTEM │ INSTALLED VERSION     │ FILTERED VULN COUNT │ FILTER REASONS │
├─────────────┼───────────┼───────────────────────┼─────────────────────┼────────────────┤
│ apt         │ Debian:12 │ 2.6.1                 │                   1 │ Unimportant    │
│ binutils    │ Debian:12 │ 2.40-2                │                   8 │ Unimportant    │
...
│ util-linux  │ Debian:12 │ 2.38.1-5+deb12u2      │                   1 │ Unimportant    │
╰─────────────┴───────────┴───────────────────────┴─────────────────────┴────────────────╯
```

</details>

### Detailed Output:

For a more detailed view of vulnerabilities, including individual **vulnerability details**, **base image identification**, and **layer specific filters**, use the HTML output format. You can enable it using:

- `--format=html`: This will output the results to an HTML file.

- `--serve`: This will generate an HTML report and host it locally on `localhost:8000`.

See the [Output documentation](./output.md) for more information on output formats.

**Sample HTML Output**:

![Screenshot of HTML output for container image scanning](./images/html-container-output.png)
