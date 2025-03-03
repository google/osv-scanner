# Migration Guide

## `v1` to `v2` migration guide

### CLI changes:

Most experimental commands have now been stablized:

- `--experimental-call-analysis` => `--call-analysis`
- `--experimental-all-packages` => `--all-packages`
- ... TODO

Container scanning and the `--docker/-D` flag has been migrated to it's own command

```bash
osv-scanner scan image <image-name>
```

`--verbosity=verbose` verbosity level removed. Now there is only `info`, `warn`, `error`

`osv-scanner <dir>` is now a shortcut for `osv-scanner scan source <dir>`

TODO: #1636?

The following deprecated flags have been removed:

- `scan --json` removed, please use `--format=json`
- `fix --disallow-major-upgrades` removed
- `fix --disallow-package-upgrades`


### JSON output changes:

License summary is now in JSON output when `--license-summary` is used, rather than showing every package.



