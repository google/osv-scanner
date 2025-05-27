---
layout: page
permalink: /usage/license-scanning/
parent: Usage
nav_order: 3
---

# License Scanning

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

OSV-Scanner supports license checking as an official feature. The data comes from the [deps.dev API](https://docs.deps.dev/api/).

## License Summary and Violations

The `--licenses` flag provides a summary of the licenses used by your dependencies.
To also display violations, you can provide an allowlist of permitted licenses as an argument:

```bash
# Show license summary only
osv-scanner --licenses path/to/repository

# Show the license summary and violations against an allowlist (provide the list after the = sign):
osv-scanner --licenses="comma-separated list of allowed licenses" path/to/directory
```

Include your allowed licenses as a comma-separated list. OSV-Scanner recognizes licenses in SPDX format. Please indicate your allowed licenses using [SPDX license](https://spdx.org/licenses/) identifiers.

### License violations example

If you wanted to allow the following licenses:

- [BSD 3-Clause "New" or "Revised" License](https://spdx.org/licenses/BSD-3-Clause.html)
- [Apache License 2.0](https://spdx.org/licenses/Apache-2.0.html)
- [MIT](https://spdx.org/licenses/MIT.html)

Your command would be in this form:

```bash
osv-scanner --licenses="BSD-3-Clause,Apache-2.0,MIT" path/to/directory
```

## Override License

Sometimes, the license either cannot be retrieved, or does not apply to your specific use. In those cases, you can override the license of a specific package by setting it in the config file.

See the [configuration docs](./configuration.md) for how to do this.
