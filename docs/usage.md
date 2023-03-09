---
layout: page
title: Usage
permalink: /usage/
nav_order: 3
---
## Usage

OSV-Scanner parses lockfiles, SBOMs, and git directories to determine your project's open source dependencies. These dependencies are matched against the OSV database via the [OSV.dev API](https://osv.dev#use-the-api) and known vulnerabilities are returned to you in the output. 

### General use case: scanning a directory

```bash
osv-scanner -r /path/to/your/dir
```

The preceding command will find lockfiles, SBOMs, and git directories in your target directory and use them to determine the dependencies to check against the OSV database for any known vulnerabilities.

The recursive flag `-r` or `--recursive` will tell the scanner to search all subdirectories in addition to the specified directory. It can find additional lockfiles, dependencies, and vulnerabilities. If your project has deeply nested subdirectories, a recursive search may take a long time. 

Git directories are searched for the latest commit hash. Searching for git commit hash is intended to work with projects that use git submodules or a similar mechanism where dependencies are checked out as real git repositories. 

### Ignored files

By default, OSV-Scanner will not scan files that are ignored by `.gitignore` files. All recursively scanned files are matched to a git repository (if it exists) and any matching `.gitignore` files within that repository are taken into account.

There is a [known issue](https://github.com/google/osv-scanner/issues/209) that the parser does not correctly respect repository boundaries.

The `--no-ignore` flag can be used to force the scanner to scan ignored files.

### Specify SBOM

If you want to check for known vulnerabilities only in dependencies in your SBOM, you can use the following command:

```bash
osv-scanner --sbom=/path/to/your/sbom.json
```

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents.

[SPDX]: https://spdx.dev/
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

### Specify Lockfile(s)
If you want to check for known vulnerabilities in specific lockfiles, you can use the following command:

```bash
osv-scanner --lockfile=/path/to/your/package-lock.json --lockfile=/path/to/another/Cargo.lock
```

It is possible to specify more than one lockfile at a time; you can also specify how to parse an arbitrary file:

```bash
osv-scanner --lockfile 'requirements.txt:/path/to/your/extra-requirements.txt'
```

A wide range of lockfiles are supported by utilizing this [lockfile package](https://github.com/google/osv-scanner/tree/main/pkg/lockfile). This is the current list of supported lockfiles:

- `buildscript-gradle.lockfile`
- `Cargo.lock`
- `composer.lock`
- `conan.lock`
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

The scanner also supports:
- `installed` files used by the Alpine Package Keeper (apk) that typically live at `/lib/apk/db/installed`
- `status` files used by the Debian Package manager (dpkg) that typically live at `/var/lib/dpkg/status`

however you must specify them explicitly using the `--lockfile` flag:

```bash
osv-scanner --lockfile 'apk-installed:/lib/apk/db/installed'
osv-scanner --lockfile 'dpkg-status:/var/lib/dpkg/status'
```

If the file you are scanning is located in a directory that has a colon in its name,
you can prefix the path to just a colon to explicitly signal to the scanner that
it should infer the parser based on the filename:

```bash
osv-scanner --lockfile ':/path/to/my:projects/package-lock.json'
```

### Scanning with call analysis
{: .note }
Features and flags with the `experimental` prefix might change or be removed with only a minor version update.

Call stack analysis can be performed on some languages to check if the 
vulnerable code is actually being executed by your project. If the code
is not being executed, these vulnerabilities will be marked as unexecuted.

To enable call analysis, call OSV-Scanner with the `--experimental-call-analysis` flag.

#### Supported languages
- `go`
  - Additional dependencies:
    - `go` compiler needs to be installed and available on PATH

#### Example
```bash
osv-scanner --experimental-call-analysis ./my/project/path
```

### Scanning a Debian based docker image packages
Preview
{: .label } 

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