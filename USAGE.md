## Table of Contents

- [Table of Contents](#table-of-contents)
- [Usage](#usage)
  - [General use case: scanning a directory](#general-use-case-scanning-a-directory)
  - [Specify SBOM](#specify-sbom)
  - [Specify Lockfile(s)](#specify-lockfiles)
  - [Scanning a Debian based docker image packages (preview)](#scanning-a-debian-based-docker-image-packages-preview)
  - [Running in a Docker Container](#running-in-a-docker-container)
- [Configure OSV-Scanner](#configure-osv-scanner)
  - [Ignore vulnerabilities by ID](#ignore-vulnerabilities-by-id)
- [Output formats](#output-formats)
  - [`table` format](#table-format)
  - [`json` format](#json-format)


## Usage

OSV-Scanner parses lockfiles, SBOMs, and git directories to determine your project's open source dependencies. These dependencies are matched against the OSV database via the [OSV.dev API](https://osv.dev#use-the-api) and known vulnerabilities are returned to you in the output. 

### General use case: scanning a directory

```console
osv-scanner -r /path/to/your/dir
```

The preceding command will find lockfiles, SBOMs, and git directories in your target directory and use them to determine the dependencies to check against the OSV database for any known vulnerabilities.

The recursive flag `-r` or `--recursive` will tell the scanner to search all subdirectories in addition to the specified directory. It can find additional lockfiles, dependencies, and vulnerabilities. If your project has deeply nested subdirectories, a recursive search may take a long time. 

Git directories are searched for the latest commit hash. Searching for git commit hash is intended to work with projects that use git submodules or a similar mechanism where dependencies are checked out as real git repositories. 

### Ignored files

By default, OSV-Scanner will not scan files that are ignored by `.gitignore` files. If the specified file is not part of a git repository, `.gitignore` files are parsed recursively starting from the target directory,
otherwise they are parsed from the root of the git repository as typical.

The `--no-ignore` flag can be used force the scanner to scan ignored files.

### Specify SBOM

If you want to check for known vulnerabilities only in dependencies in your SBOM, you can use the following command:

```console
osv-scanner --sbom=/path/to/your/sbom.json
```

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents.

[SPDX]: https://spdx.dev/
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

### Specify Lockfile(s)
If you want to check for known vulnerabilities in specific lockfiles, you can use the following command:

```console
osv-scanner --lockfile=/path/to/your/package-lock.json --lockfile=/path/to/another/Cargo.lock
```

It is possible to specify more than one lockfile at a time; you can also specify how to parse an arbitrary file:

```console
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

The scanner also supports `installed` files used by the Alpine Package Keeper (apk) that typically live at `/lib/apk/db/installed`,
however you must specify this explicitly using the `--lockfile` flag:

```console
osv-scanner --lockfile 'apk-installed:/lib/apk/db/installed'
```

If the file you are scanning is located in a directory that has a colon in its name,
you can prefix the path to just a colon to explicitly signal to the scanner that
it should infer the parser based on the filename:

```bash
$ osv-scanner --lockfile ':/path/to/my:projects/package-lock.json'
```

### Scanning a Debian based docker image packages (preview)

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

This currently does not scan the filesystem of the Docker container, and has various other limitations. Follow [this issue](https://github.com/google/osv-scanner/issues/64) for updates on container scanning!

#### Example

```console
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

## Configure OSV-Scanner

To configure scanning, place an osv-scanner.toml file in the scanned file's directory. To override this osv-scanner.toml file, pass the `--config=/path/to/config.toml` flag with the path to the configuration you want to apply instead.

Currently, there is only 1 option to configure:

### Ignore vulnerabilities by ID

To ignore a vulnerability, enter the ID under the `IgnoreVulns` key. Optionally, add an expiry date or reason.

#### Example

```toml
[[IgnoredVulns]]
id = "GO-2022-0968"
# ignoreUntil = 2022-11-09 # Optional exception expiry date
reason = "No ssh servers are connected to or hosted in Go lang"

[[IgnoredVulns]]
id = "GO-2022-1059"
# ignoreUntil = 2022-11-09 # Optional exception expiry date
reason = "No external http servers are written in Go lang."
```

## Output formats

You can control the format used by the scanner to output results with the `--format` flag. The different formats supported by the scanner are:

### `table` format

The default format, which outputs the results as a human-readable table.

Sample output:

```
╭─────────────────────────────────────┬───────────┬──────────────────────────┬─────────┬────────────────────╮
│ OSV URL (ID IN BOLD)                │ ECOSYSTEM │ PACKAGE                  │ VERSION │ SOURCE             │
├─────────────────────────────────────┼───────────┼──────────────────────────┼─────────┼────────────────────┤
│ https://osv.dev/GHSA-c3h9-896r-86jm │ Go        │ github.com/gogo/protobuf │ 1.3.1   │ path/to/go.mod     │
│ https://osv.dev/GHSA-m5pq-gvj9-9vr8 │ crates.io │ regex                    │ 1.3.1   │ path/to/Cargo.lock │
╰─────────────────────────────────────┴───────────┴──────────────────────────┴─────────┴────────────────────╯
```

### `json` format

Outputs the results as a JSON object to stdout, with all other output being directed to stderr - this makes it safe to redirect the output to a file with `osv-scanner --format json ... > /path/to/file.json`.

Sample output:

```json5
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
              ]
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
