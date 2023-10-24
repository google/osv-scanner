---
layout: page
title: Usage
permalink: /usage/
nav_order: 3
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

### Custom Lockfiles

If you have a custom lockfile that we do not support or prefer to do your own custom parsing, you can extract the custom lockfile information and create a custom intermediate file containing dependency information so that osv-scanner can still check for vulnerabilities.

Once you extracted your own dependency information, place it in a `osv-scanner.json` file, with the same format as the JSON output of osv-scanner, e.g.:

```
{
  "results": [
    {
      "packages": [
        {
          "package": {
            "name": "github.com/repo/url",
            "commit": "9a6bd55c9d0722cb101fe85a3b22d89e4ff4fe52"
          }
        },
        {
          "package": {
            "name": "react",
            "version": "1.2.3",
            "ecosystem": "npm"
          }
        },
        // ...
      ]
    }
  ]
}
```

Then pass this to `osv-scanner` with this:
```
osv-scanner --lockfile osv-scanner:/path/to/osv-scanner.json
```

## Scanning a Debian based docker image packages
Preview
{: .label }

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

This currently does not scan the filesystem of the Docker container, and has various other limitations. Follow [this issue](https://github.com/google/osv-scanner/issues/64) for updates on container scanning!

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
