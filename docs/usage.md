---
layout: page
title: Usage
permalink: /usage/
nav_order: 4
---

# Usage

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

All OSV-Scanner commands consists of an initial package extraction step, and then some actions on the extracted result (e.g. match vulnerabilities, update packages...).

## Subcommands

OSV-Scanner V2 is broken down into several subcommands:

| Subcommand    | Documentation Link                                   | Quick Example                                                          |
| ------------- | ---------------------------------------------------- | ---------------------------------------------------------------------- |
| `scan`        | [Further down this page](./usage.md#scan-subcommand) | `osv-scanner scan -r ./my-project-dir/`                                |
| `scan source` | [Source Project Scanning]()                          | Source scanning is default, so save as above.                          |
| `scan image`  | [Container Scanning](./container-image-scanning.md)  | `osv-scanner scan image my-docker-img:latest`                          |
| `fix`         | [Guided Remediation](./guided-remediation.md)        | `osv-scanner fix -M path/to/package.json -L path/to/package-lock.json` |


## Scan Subcommand

The `scan` subcommand has two subcommands of its own, `source` (default) or `image`.

See the following pages to see more usage details of these commands.

- [Scanning Source](./scan-source.md)
- [Scanning Container Images](./scan-image.md)

Both of these commands share many flags to configure what happens after the initial package extraction step:

## Post extraction flags:

### Saving to file

The `--output` flag can be used to save the scan results to a file instead of being printed on the stdout:

```bash
osv-scanner scan -L package-lock.json --output scan-results.txt
```

### Setting output format

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

There are also some features gated behind experimental flags that apply to all scan commands, see their respective pages for more details

- [`--experimental-offline-vulnerabilities`](./offline-mode.md)
- [`--experimental-licenses`](./license-scanning.md)
- `--experimental-no-resolve`
  - Turns off transitive dependency resolution for supported ecosystems.
- `experimental-all-packages`
  - Outputs all packages in the json output format.

## Pre-commit integration

If you wish to install OSV-Scanner as a [pre-commit](https://pre-commit.com) plugin in your project, you may use the `osv-scanner` pre-commit hook. Use the `args` key in your `.pre-commit-config.yaml` to pass your command-line arguments as you would using OSV-Scanner in the command line.

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

The simplest way to get the osv-scanner docker image is to pull from GitHub Container Registry:

```bash
docker pull ghcr.io/google/osv-scanner:latest
```

Once you have the image, you can test that it works by running:

```bash
docker run -it ghcr.io/google/osv-scanner -h
```

Finally, to run it, mount the directory you want to scan to `/src` and pass the
appropriate osv-scanner flags:

```bash
docker run -it -v ${PWD}:/src ghcr.io/google/osv-scanner -L /src/go.mod
```

