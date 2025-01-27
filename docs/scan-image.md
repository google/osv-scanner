---
layout: page
title: Container Image Scanning
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

OSV-Scanner supports scanning container images for deployed artifacts with security vulnerabilities.

Optional Requirement:
 - `docker` command to be installed and available on the `PATH`. This is only required if you do not wish to save the image you want to scan onto disk in a compatible format before scanning.

All image scanning is done with the `scan image` subcommand: `osv-scanner scan image`.

## Scan docker image

```bash
osv-scanner scan image image-name:tag
```

If the image `name:tag` exists locally, it will use that image, otherwise pull from the appropriate image registry. This requires docker to be installed and available to be called by osv-scanner, as we essentially run `docker save name:tag > temporary-file.tar`, then scan the exported tar.

No files within the container image are executed.

## Scan exported image archive:

If you have already exported the image as a docker archive, you can directly scan it with the `--local` flag:

```bash
osv-scanner scan image --local ./path/to/img.tar
```

This does not require any docker or any other dependencies to be installed.

To create the image archive from your local images, this can be done with any of these commands:

```bash
# With Docker
docker save name-of-image:tag > img.tar
# With Podman
podman save --format=docker-archive name-of-image:tag > img.tar
# With other image builders, use the docker archive format to export the tar
```

## Additional Flags

When performing container scanning, no other targets other than the container itself can be specified. However, you can still perform all the configuration flags specified on the [Usage](./usage.md) page.

# Output

By default, because of the large number of vulnerabilities that many images have, we do not show each vulnerability individually, but group them together into packages.

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

---

To view all the vulnerabilities, and get a more detailed container image report, try out html output format. It can be activated by either using the `--format=html` flag, or via the `--serve` flag to host the output on `localhost:8000`.

See more details of the html output on the [output page](./output.md).


<details markdown="1">
<summary><b>Sample HTML output</b></summary>

![Screenshot of HTML output for container image scanning](./images/html-container-output.png)

</details>
