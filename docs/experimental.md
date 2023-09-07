---
layout: page
title: Experimental Features
permalink: /experimental/
nav_order: 6
---
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

{: .note }
Features and flags with the `experimental` prefix might change or be removed with only a minor version update.

OSV-Scanner now supports offline scanning as an experimental feature. Offline scanning checks your project against a local database instead of calling the OSV.dev API. Local copies of dependencies are not required because version comparison is done using Go-based implementation of each ecosystems version specificiation. OSV-Scanner does not callout to dependency managers when using `--experimental-local-db` or `--experimental-offline` flags. 

### Local database option

The local database flag `--experimental-local-db` causes OSV-Scanner to download or update your local database and then scan your project against it. 

```bash
osv-scanner --experimental-local-db ./path/to/your/dir
```

### Offline option
The offline database flag `--experimental-offline` causes OSV-Scanner to scan your project against a previously downloaded local database. OSV-Scanner will not download or update the local database. When a local database is not present, you will get an error message.

```bash
osv-scanner --experimental-offline ./path/to/your/dir
```

### Manual database download
Instead of using the `--experimental-local-db` flag to download the database, it is possible to manually download the database. 

A downloadable copy of the OSV database is stored in a GCS bucket maintained by OSV:
[`gs://osv-vulnerabilities`](https://osv-vulnerabilities.storage.googleapis.com)

This bucket contains individual entries of the format
`gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json` as well as a zip containing all
vulnerabilities for each ecosystem at
`gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`.

E.g. for PyPI vulnerabilities:

```bash
gsutil cp gs://osv-vulnerabilities/PyPI/all.zip .
```

You can also download over HTTP via https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip

A list of all current ecosystems is available at 
[`gs://osv-vulnerabilities/ecosystems.txt`](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)

When run with the `--experimental-local-db` flag, OSV-Scanner downloads the database into the following file structure:

```
{local_db_dir}/
  osv-scanner/
    npm/all.zip
    PyPI/all.zip
    …
    {ecosystem}/all.zip
```

If you manually dowload the files are store them in the same file structure, OSV-Scanner will be able to find the database when using the `--experimental-offline` flag. 

### Limitations

1. Commit level scanning is not supported. 