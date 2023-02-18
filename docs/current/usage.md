---
layout: page
title: Usage
permalink: /usage/
nav_order: 3
---
OSV-Scanner collects a list of dependencies and versions that are used in your project, before matching this list against the OSV database via the [OSV.dev API](https://osv.dev#use-the-api). To build the list of dependencies, you can point OSV-Scanner at your project directory, or manually pass in the path to individual manifest files.

### Scan a directory

Walks through a list of directories to find:

- Lockfiles
- SBOMs
- git directories for the latest commit hash

which is used to build the list of dependencies to be matched against OSV vulnerabilities.

Can be configured to recursively walk through subdirectories with the `--recursive` / `-r` flag.

Searching for git commit hash is intended to work with projects that use
git submodules or a similar mechanism where dependencies are checked out
as real git repositories.

#### Example

```bash
osv-scanner -r /path/to/your/dir
```

### Input an SBOM

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents.

[SPDX]: https://spdx.dev/
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

#### Example

```bash
osv-scanner --sbom=/path/to/your/sbom.json
```

### Input a lockfile

A wide range of lockfiles are supported by utilizing this [lockfile package](https://github.com/google/osv-scanner/tree/main/pkg/lockfile). This is the current list of supported lockfiles:

- `buildscript-gradle.lockfile`
- `Cargo.lock`
- `composer.lock`
- `Gemfile.lock`
- `go.mod`
- `gradle.lockfile`
- `mix.lock`
- `package-lock.json`
- `packages.lock.json`
- `Pipfile.lock`
- `pnpm-lock.yaml`
- `poetry.lock`
- `pom.xml`[\*](https://github.com/google/osv-scanner/issues/35)
- `pubspec.lock`
- `requirements.txt`[\*](https://github.com/google/osv-scanner/issues/34)
- `yarn.lock`
- `/lib/apk/db/installed` (Alpine)

#### Example

```bash
osv-scanner --lockfile=/path/to/your/package-lock.json --lockfile=/path/to/another/Cargo.lock
```

### Scanning a Debian based docker image packages (preview)

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

This currently does not scan the filesystem of the Docker container, and has various other limitations. Follow [this issue](https://github.com/google/osv-scanner/issues/64) for updates on container scanning!

#### Example

```bash
osv-scanner --docker image_name:latest
```

### Running in a Docker Container

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
