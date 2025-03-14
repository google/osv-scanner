# Migration Guide

## `v1` to `v2` migration guide

### CLI changes:

Most experimental commands have now been stablized, all experimental versions of these flags have been removed:

- `--experimental-call-analysis` => `--call-analysis`
- `--experimental-no-call-analysis` => `--no-call-analysis`
- `--experimental-all-packages` => `--all-packages`
- `--experimental-licenses` & `--experimental-license-summary` => `--licenses`
  - Instead of two separate flags, by having no values after `--licenses`, it behaves the same way as just `--experimental-license-summary`
  - You can still specify the license allow list after `--licenses` flag like so: `--licenses="MIT,Apache 2.0,..."`
- `--experimental-offline` => `--offline`
- `--experimental-offline-vulnerabilities` => `--offline-vulnerabilities`
- `--experimental-download-offline-databases` => `--offline-download-offline-databases`
- `--experimental-no-resolve` => `--no-resolve`

---

Container scanning and the `--docker/-D` flag has been migrated to it's own command.

```bash
osv-scanner scan image <image-name>
```

---

[Guided remeidation](https://google.github.io/osv-scanner/experimental/guided-remediation/) now defaults to the non-interactive mode. To run in the interactive mode, use the `--interactive` flag.

---

`--verbosity=verbose` verbosity level removed. Now there are only `info`, `warn`, `error` verbosity levels.

---

`osv-scanner <dir>` is now a shortcut for `osv-scanner scan source <dir>`.

---

SBOM scanning (`osv-scanner --sbom`) now relies on the filename of the sbom file to follow the relevant SBOM specs. E.g. `*.spdx.json`.

---

The `.git` root hash directory is not automatically scanned now, therefore:

`--skip-git` flag removed, replaced with `--include-git-root`.

---

The following deprecated flags have been removed:

- `scan --json` removed, please use `--format=json`
- `fix --disallow-major-upgrades` removed
- `fix --disallow-package-upgrades`

### JSON output changes:

License summary is now in JSON output when `--license-summary` is used, rather than showing every package.
