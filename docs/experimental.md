---
layout: page
title: Experimental Features
permalink: /experimental/
nav_order: 7
---
# Experimental Features

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

{: .note }
Features and flags with the `experimental` prefix might change or be removed with only a minor version update.

## Scanning with call analysis  

Call stack analysis can be performed on some languages to check if the 
vulnerable code is actually being executed by your project. If the code
is not being executed, these vulnerabilities will be marked as unexecuted.

To enable call analysis, call OSV-Scanner with the `--experimental-call-analysis` flag.

### Call analysis in Go

OSV-Scanner uses the `govulncheck` library to analyze Go source code to identify called vulnerable functions.

#### Additional Dependencies

`go` compiler needs to be installed and available on `PATH`    

### Call analysis in Rust

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
osv-scanner --experimental-call-analysis ./my/project/path
```

## Offline mode

OSV-Scanner now supports offline scanning as an experimental feature. Offline scanning checks your project against a local database instead of calling the OSV.dev API.

### Specify database location

Our offline features require the use of a local database, the location of which is determined through the use of the `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` environment variable. 

The local database file structure is in this form:

```
{local_db_dir}/
  osv-scanner/
    npm/all.zip
    PyPI/all.zip
    …
    {ecosystem}/all.zip
```

Where `{local_db_dir}` can be set by the `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` environment variable. 

If the `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` environment variable is _not_ set, OSV-Scanner will attempt to look for the database in the following locations, in this order: 

1. The location returned by [`os.UserCacheDir`](https://pkg.go.dev/os#UserCacheDir)
2. The location returned by [`os.TempDir`](https://pkg.go.dev/os#TempDir)

The database can be [downloaded manually](./experimental.md#manual-database-download) or by using the [`--experimental-local-db` flag](./experimental.md#local-database-option). 

### Offline option
The offline database flag `--experimental-offline` causes OSV-Scanner to scan your project against a previously downloaded local database. OSV-Scanner will not download or update the local database, nor will it send any project or dependency information anywhere. When a local database is not present, you will get an error message. No network connection is required when using this flag.  

```bash
osv-scanner --experimental-offline ./path/to/your/dir
```

### Local database option

The local database flag `--experimental-local-db` causes OSV-Scanner to download or update your local database and then scan your project against it. 

```bash
osv-scanner --experimental-local-db ./path/to/your/dir
```

### Manual database download
Instead of using the `--experimental-local-db` flag to download the database, it is possible to manually download the database. 

A downloadable copy of the OSV database is stored in a GCS bucket maintained by OSV:
[`gs://osv-vulnerabilities`](https://osv-vulnerabilities.storage.googleapis.com)

This bucket contains zip files  containing all vulnerabilities for each ecosystem at:
`gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`.

E.g. for PyPI vulnerabilities:

```bash
gsutil cp gs://osv-vulnerabilities/PyPI/all.zip .
```

You can also download over HTTP via https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip .

A list of all current ecosystems is available at 
[`gs://osv-vulnerabilities/ecosystems.txt`](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt).

Set the location of your manually downloaded database by following the instructions [here](./experimental.md#specify-database-location).

### Limitations

1. Commit level scanning is not supported. 
