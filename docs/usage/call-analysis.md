---
layout: page
title: Call Analysis
permalink: /usage/call-analysis/
parent: Usage
nav_order: 2
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
## Scanning with call analysis  

{: .note }
Features and flags with the `experimental` prefix might change or be removed with only a minor version update.

Call stack analysis can be performed on some languages to check if the 
vulnerable code is actually being executed by your project. If the code
is not being executed, these vulnerabilities will be marked as unexecuted.

To enable call analysis, call OSV-Scanner with the `--experimental-call-analysis` flag.

### Supported languages

---

#### **Go**

OSV-Scanner uses the `govulncheck` library to analyze Go source code to identify called vulnerable functions.

##### Additional Dependencies

`go` compiler needs to be installed and available on `PATH`    

---

#### **Rust**

OSV-Scanner compiles Rust source code and analyzes the output binary's DWARF debug information to identify called vulnerable functions.

##### Additional Dependencies

Rust toolchain (including `cargo`) that can compile the source code being scanned needs to be installed and available on `PATH`.

The installed Rust toolchain must be capable of compiling every crate/target in the scanned code, for code with
a lot of dependencies this will take a few minutes.

##### **Limitations**

Current implementation has a few limitations:

- Does not support dependencies on proc-macros (Tracked in [#464](https://github.com/google/osv-scanner/issues/464))
- Does not support any dependencies that are dynamically linked
- Does not support dependencies that link external non-rust code

---

### Example
```bash
osv-scanner --experimental-call-analysis ./my/project/path
```