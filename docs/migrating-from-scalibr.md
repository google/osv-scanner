---
layout: default
title: Migrating from osv-scalibr
nav_order: 18
---

# Migrating from osv-scalibr to osv-scanner

This guide is for users who are familiar with `osv-scalibr` and want to migrate to `osv-scanner`. It explains how to
achieve similar results with `osv-scanner`.

`osv-scanner` has integrated `osv-scalibr`'s inventory collection and vulnerability scanning capabilities.
While most of `osv-scalibr`'s functionalities are available in `osv-scanner`, the command-line flags and output formats
are different.

## Command-line Equivalence

The `osv-scanner` CLI is designed to be more intuitive and user-friendly. Here's a mapping of common `osv-scalibr`
commands to their `osv-scanner` equivalents.

### Scanning a directory

**osv-scalibr:**

```sh
scalibr --root /path/to/your/project --result result.json
```

**osv-scanner:**

```sh
osv-scanner /path/to/your/project
```

### Selecting plugins

OSV-Scanner has access to the full list of OSV-Scalibr plugins, though only a well tested subset of them are enabled by
default in OSV-Scanner.

In `osv-scalibr`, you can select which plugins to run using the `--extractors`, `--detectors` flags,
or alternatively using the `--plugins` flag.

For a full list of available plugin names, see OSV-Scalibr's documentation here:
https://github.com/google/osv-scalibr/blob/main/docs/supported_inventory_types.md

**osv-scalibr:**

```sh
scalibr --plugins python/pip,go/gomod --detectors go/govulncheck /path/to/your/project
```

In `osv-scanner`, you can achieve the same by using the `--experimental-plugins` flag. This is an experimental feature.

**osv-scanner:**

```sh
osv-scanner --experimental-plugins python/pip,go/gomod,go/govulncheck /path/to/your/project
```

`osv-scanner` lets you exclude its default plugins with `--experimental-no-default-plugins`, for when you want to only
run specific plugins.

`osv-scanner` also allows you to disable specific plugins with `--experimental-disable-plugins`.

For more details on manual plugin selection in `osv-scanner`, see the [manual plugin selection documentation](manual-plugin-selection.md).

### Generating SPDX output

`osv-scalibr` uses the `-o` flag to specify the output format and file. For example, to generate an SPDX JSON report:

**osv-scalibr:**

```sh
scalibr -o spdx23-json=result.spdx.json /path/to/your/project
```

`osv-scanner` uses the `--format` flag to specify the output format and the output is written to standard output,
and a separate `--output-file` flag if you wish to save the output into a file.

**osv-scanner:**

```sh
osv-scanner --format spdx-2.3-json /path/to/your/project > result.spdx.json
```

For more details on `osv-scanner` output formats, see the [output documentation](output.md).

## Flag Translation Table

| `osv-scalibr` Flag                | `osv-scanner` Flag        | Notes                                                                                                      |
| --------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `--version`                       | `--version`               | `osv-scanner version`                                                                                      |
| `--root`                          | `[directory]` (argument)  | `osv-scanner scan source [directory]`                                                                      |
| `--result`                        | `--output`                | `osv-scanner --output <file>`                                                                              |
| `-o`                              | `--format` and `--output` | e.g. `osv-scalibr -o spdx23-json=r.json` becomes `osv-scanner --format spdx-2.3-json --output-file r.json` |
| `--plugins`                       | `--experimental-plugins`  |                                                                                                            |
| `--extractors`                    | `--experimental-plugins`  |                                                                                                            |
| `--detectors`                     | `--experimental-plugins`  |                                                                                                            |
| `--annotators`                    | `--experimental-plugins`  |                                                                                                            |
| `--ignore-sub-dirs`               | (no direct equivalent)    | `osv-scanner` is not recursive by default. Use `--recursive` to enable.                                    |
| `--skip-dirs`                     | Not yet available         |                                                                                                            |
| `--skip-dir-regex`                | Not yet available         |                                                                                                            |
| `--skip-dir-glob`                 | Not yet available         |                                                                                                            |
| `--max-file-size`                 | Not yet available         |                                                                                                            |
| `--use-gitignore`                 | (default behavior)        | Use `--no-ignore` to disable.                                                                              |
| `--remote-image`                  | `[image]` (argument)      | `osv-scanner scan image [image]`                                                                           |
| `--image-tarball`                 | `--archive`               | `osv-scanner scan image --archive [tarball]`                                                               |
| `--image-local-docker`            | `[image]` (argument)      | `osv-scanner scan image [image]` (it will look for local images first)                                     |
| `--image-platform`                | Not yet available         |                                                                                                            |
| `--gobinary-version-from-content` | Not yet available         |                                                                                                            |
| `--govulncheck-db`                | Not yet available         |                                                                                                            |
| `--spdx-document-name`            | Not yet available         |                                                                                                            |
| `--spdx-document-namespace`       | Not yet available         |                                                                                                            |
| `--spdx-creators`                 | Not yet available         |                                                                                                            |
| `--cdx-component-name`            | Not yet available         |                                                                                                            |
| `--cdx-component-type`            | Not yet available         |                                                                                                            |
| `--cdx-component-version`         | Not yet available         |                                                                                                            |
| `--cdx-authors`                   | Not yet available         |                                                                                                            |
| `--verbose`                       | `--verbosity`             | `osv-scanner --verbosity <level>`, e.g. `debug`.                                                           |
| `--explicit-extractors`           | (default behavior)        |                                                                                                            |
| `--filter-by-capabilities`        | (default behavior)        | `osv-scanner` automatically filters plugins.                                                               |
| `--windows-all-drives`            | Not yet available         |                                                                                                            |
| `--offline`                       | `--offline`               |                                                                                                            |
| `--local-registry`                | `--maven-registry`        | Only for Maven.                                                                                            |
