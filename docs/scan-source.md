---
layout: page
parent: Usage
permalink: /usage/scan-source
nav_order: 2
---

# Project Source Scanning

OSV-Scanner can be used to scan your project source and lockfiles to find vulnerabilities in your dependencies.

```bash
osv-scanner scan source <flags> [paths...]
```

As this is the most common use case of osv-scanner, `scan source` is the default subcommand of osv-scanner, so the above is equivalent to:

```bash
osv-scanner <flags> [paths...]
```

## General use case: scanning a directory

```bash
osv-scanner scan source -r /path/to/your/dir
```

The preceding command will find lockfiles, SBOMs, and git directories in your target directory and use them to determine the dependencies to check against the OSV database for any known vulnerabilities.

The recursive flag `-r` or `--recursive` will tell the scanner to search all subdirectories in addition to the specified directory. It can find additional lockfiles, dependencies, and vulnerabilities. If your project has deeply nested subdirectories, a recursive search may take a long time.

## Ignored files

By default, OSV-Scanner will not scan files that are ignored by `.gitignore` files. All recursively scanned files are matched to a git repository (if it exists) and any matching `.gitignore` files within that repository are taken into account.

There is a [known issue](https://github.com/google/osv-scanner/issues/209) that the parser does not correctly respect repository boundaries.

The `--no-ignore` flag can be used to force the scanner to scan ignored files.

## Specify SBOM

If you want to check for known vulnerabilities only in dependencies in your SBOM, you can use the following command:

```bash
osv-scanner scan source --sbom=/path/to/your/sbom.spdx.json
```

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported.

To identify the correct SBOM format, the file name must follow the SBOM specifications for each format:

- [SPDX Filenames]:
  - `*.spdx.json`
  - `*.spdx`
  - `*.spdx.yml`
  - `*.spdx.rdf`
  - `*.spdx.rdf.xml`
- [CycloneDX Filenames]:
  - `bom.json`
  - `*.cdx.json`
  - `bom.xml`
  - `*.cdx.xml`

[SPDX]: https://spdx.dev/
[SPDX Filenames]: https://spdx.github.io/spdx-spec/v2.3/conformance/
[CycloneDX Filenames]: https://cyclonedx.org/specification/overview/#recognized-file-patterns
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

## Specify Lockfile(s)

If you want to check for known vulnerabilities in specific lockfiles, you can use the following command:

```bash
osv-scanner scan source --lockfile=/path/to/your/package-lock.json --lockfile=/path/to/another/Cargo.lock
```

It is possible to specify more than one lockfile at a time; you can also specify how to parse an arbitrary file:

```bash
osv-scanner scan source --lockfile 'requirements.txt:/path/to/your/extra-requirements.txt'
```

The list of supported lockfile formats can be found [here](./supported_languages_and_lockfiles.md).

If the file you are scanning is located in a directory that has a colon in its name,
you can prefix the path to just a colon to explicitly signal to the scanner that
it should infer the parser based on the filename:

```bash
osv-scanner scan source --lockfile ':/path/to/my:projects/package-lock.json'
```

## Git Repository Scanning

OSV-Scanner will automatically scan git submodules and vendored directories for C/C++ code and try to attribute them to specific dependencies and versions. See [C/C++ Scanning](./supported_languages_and_lockfiles.md#cc-scanning) for more details.

By default, root git directories (i.e. git repositories that are not a submodule of a bigger git repo) are skipped. You can include those repositories by setting the `--include-git-root` flag.

## Scanning with call analysis

Call stack analysis can be performed on some languages to check if the
vulnerable code is actually being executed by your project. If the code
is not being executed, these vulnerabilities will be marked as unexecuted.

To enable call analysis in all languages, call OSV-Scanner with the `--call-analysis=all` flag. By default, call analysis in Go is enabled, but you can disable it using the `--no-call-analysis=go` flag.

### Call analysis in Go

OSV-Scanner uses the [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) library to analyze Go source code to identify called vulnerable functions.

#### Additional Dependencies

`go` compiler needs to be installed and available on `PATH`.

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
osv-scanner scan source --call-analysis=rust --no-call-analysis=go ./my/project/path
```
