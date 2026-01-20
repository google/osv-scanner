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

## Excluding Paths

Experimental
{: .label }

You can exclude specific paths from scanning using the `--experimental-exclude` flag. This is useful for excluding test directories, documentation, or vendor directories from vulnerability scans.

**Note:** This flag currently only excludes directories, not individual files. This is an experimental feature and the syntax may change in future versions.

### Syntax

The flag supports three pattern types, matching the `--lockfile` flag syntax:

- **Exact directory name** (no prefix or `:` prefix): Matches directories with the exact name
- **Glob pattern** (`g:` prefix): Matches using glob patterns
- **Regex pattern** (`r:` prefix): Matches using regular expressions

### Examples

```bash
# Exclude directories named "test" or "docs" (exact match)
osv-scanner scan source -r --experimental-exclude=test --experimental-exclude=docs /path/to/your/dir

# Exclude using glob patterns
osv-scanner scan source -r --experimental-exclude="g:**/test/**" --experimental-exclude="g:**/docs/**" /path/to/your/dir

# Exclude using regex patterns
osv-scanner scan source -r --experimental-exclude="r:.*_test$" /path/to/your/dir

# Mix different pattern types
osv-scanner scan source -r --experimental-exclude=vendor --experimental-exclude="g:**/test/**" --experimental-exclude="r:\\.cache" /path/to/your/dir

# Escape directory names containing colons using : prefix
osv-scanner scan source -r --experimental-exclude=":my:project" /path/to/your/dir
```

### Common use cases

- Excluding test directories: `--experimental-exclude=test` or `--experimental-exclude="g:**/test/**"`
- Excluding documentation: `--experimental-exclude=docs`
- Excluding vendor directories: `--experimental-exclude=vendor`

Alternatively, you can use the `osv-scanner.toml` configuration file with `[[PackageOverrides]]` to ignore specific packages or directories. See [Configuration](./configuration.md) for more details.

## SBOM scanning

SBOMs will be automatically identified so long as their name follows the specification for the particular format:

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

```bash
osv-scanner scan source -L /path/to/your/sbom.spdx.json
```

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported.

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
