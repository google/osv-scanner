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

OSV-Scanner now supports offline scanning as an experimental feature. Offline scanning checks your project against a local database instead of calling the OSV.dev API.

### Local Database Option

The local database flag `--experimental-local-db` causes OSV-Scanner to download or update your local database and then scan your project against it. 

```bash
osv-scanner --experimental-local-db ./path/to/your/dir
```

### Offline option
The offline database flag `--experimental-offline` causes OSV-Scanner to scan your project against a previously downloaded local database. OSV-Scanner will not download or update the local database. When a local database is not present, you will get an error message.

```bash
osv-scanner --experimental-offline ./path/to/your/dir
```