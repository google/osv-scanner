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

## General use case: scanning a directory

```bash
osv-scanner -r /path/to/your/dir
```

The preceding command will find lockfiles, SBOMs, and git directories in your target directory and use them to determine the dependencies to check against the OSV database for any known vulnerabilities.

The recursive flag `-r` or `--recursive` will tell the scanner to search all subdirectories in addition to the specified directory. It can find additional lockfiles, dependencies, and vulnerabilities. If your project has deeply nested subdirectories, a recursive search may take a long time.

Git directories are searched for the latest commit hash. Searching for git commit hash is intended to work with projects that use git submodules or a similar mechanism where dependencies are checked out as real git repositories.

## Ignored files

By default, OSV-Scanner will not scan files that are ignored by `.gitignore` files. All recursively scanned files are matched to a git repository (if it exists) and any matching `.gitignore` files within that repository are taken into account.

There is a [known issue](https://github.com/google/osv-scanner/issues/209) that the parser does not correctly respect repository boundaries.

The `--no-ignore` flag can be used to force the scanner to scan ignored files.

## Specify SBOM

If you want to check for known vulnerabilities only in dependencies in your SBOM, you can use the following command:

```bash
osv-scanner --sbom=/path/to/your/sbom.spdx.json
```

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents and the file name.

When scanning a directory, only SBOMs following the specification filename will be scanned. See the specs for [SPDX Filenames] and [CycloneDX Filenames].

[SPDX]: https://spdx.dev/
[SPDX Filenames]: https://spdx.github.io/spdx-spec/v2.3/conformance/
[CycloneDX Filenames]: https://cyclonedx.org/specification/overview/#recognized-file-patterns
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

## Specify Lockfile(s)

If you want to check for known vulnerabilities in specific lockfiles, you can use the following command:

```bash
osv-scanner --lockfile=/path/to/your/package-lock.json --lockfile=/path/to/another/Cargo.lock
```

It is possible to specify more than one lockfile at a time; you can also specify how to parse an arbitrary file:

```bash
osv-scanner --lockfile 'requirements.txt:/path/to/your/extra-requirements.txt'
```

The list of supported lockfile formats can be found [here](/osv-scanner/supported-languages-and-lockfiles/).

If the file you are scanning is located in a directory that has a colon in its name,
you can prefix the path to just a colon to explicitly signal to the scanner that
it should infer the parser based on the filename:

```bash
osv-scanner --lockfile ':/path/to/my:projects/package-lock.json'
```

## Scanning a Debian based docker image packages

Preview
{: .label }

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

This currently does not scan the filesystem of the Docker container, and has various other limitations. Follow [this issue](https://github.com/google/osv-scanner/issues/64) for updates on container scanning!

{: .warning }
Only run this on a trusted container image, as it runs the container image to retrieve the package versions.

### Example

```bash
osv-scanner --docker image_name:latest
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

## Saving to file

The `--output` flag can be used to save the scan results to a file instead of being printed on the stdout:

```bash
osv-scanner -L package-lock.json --output scan-results.txt
```

## C/C++ scanning

OSV-Scanner supports C/C++ projects.

Because the C/C++ ecosystem does not have a centralized package manager, C/C++ dependencies tend to be bundled with the project's source code. Dependencies are either [submoduled](#submoduled-dependencies) or [vendored](#vendored-dependencies). In either case, OSV-Scanner is able to find known vulnerabilities in your project dependencies.

OSV-Scanner's C/C++ support is based on commit-level data. OSV's commit-level data covers the majority of C/C++ vulnerabilities within the OSV database, but users should be aware that there may be vulnerabilities in their dependencies that may not be in the OSV database and therefore not included in OSV-Scanner results. Adding more commit-level data to the database is an ongoing project, follow [#783](https://github.com/google/osv.dev/issues/783) for more details.

### Submoduled dependencies

[Submoduled](https://git-scm.com/book/en/v2/Git-Tools-Submodules) dependencies are included in the project's source code and retain their Git histories. To scan a C/C++ project with submoduled dependencies:

1. Navigate to the root folder of your project.
2. Ensure that your submodules are up to date using `git submodule update`.
3. Run scanner using `osv-scanner -r .`.

### Vendored dependencies

Vendored dependencies have been directly copied into the project folder, but do not retain their Git histories. OSV-Scanner uses OSV's [determineversion API](https://google.github.io/osv.dev/post-v1-determineversion/) to estimate each dependency's version (and associated Git commit). Vulnerabilities for the estimated version are returned. This process requires no additional work from the user. Run OSV-Scanner as you normally would.

## Scanning with call analysis

Call stack analysis can be performed on some languages to check if the
vulnerable code is actually being executed by your project. If the code
is not being executed, these vulnerabilities will be marked as unexecuted.

To enable call analysis in all languages, call OSV-Scanner with the `--call-analysis=all` flag. By default, call analysis in Go is enabled, but you can disable it using the `--no-call-analysis=go` flag.

### Call analysis in Go

OSV-Scanner uses the [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) library to analyze Go source code to identify called vulnerable functions.

#### Additional Dependencies

`go` compiler needs to be installed and available on `PATH`

### Call analysis in Rust

Experimental
{: .label }

Call analysis in Rust is still considered experimental.

OSV-Scanner compiles Rust source code and analyzes the output binary's DWARF debug information to identify called vulnerable functions.

#### Additional Dependencies

Rust toolchain (including `cargo`) that can compile the source code being scanned needs to be installed and available on `PATH`.

The installed Rust toolchain must be capable of compiling every crate/target in the scanned code, for code with
a lot of dependencies this will take a few minutes.

### Limitations

Current implementation has a few limitations:

- Does not support dependencies on proc-macros (Tracked in [#464](https://github.com/google/osv-scanner/issues/464))
- Does not support any dependencies that are dynamically linked
- Does not support dependencies that link external non-rust code

### Example

```bash
osv-scanner --call-analysis=rust --no-call-analysis=go ./my/project/path
```

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
