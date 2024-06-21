---
layout: page
title: License Scanning
permalink: /experimental/license-scanning/
parent: Experimental Features
nav_order: 2
---

# License Scanning

Experimental
{: .label }

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

OSV-Scanner supports license checking as an experimental feature. The data comes from the [deps.dev API](https://docs.deps.dev/api/).

{: .note }
This feature is experimental and might change or be removed with only a minor version update.

## License summary

If you want a summary of your dependencies licenses, use the `--experimental-licenses-summary` flag:

```bash
osv-scanner --experimental-licenses-summary path/to/repository
```

## License violations

To set an allowed license list and see the details of packages that do not conform, use the `--experimental-licenses` flag:

```bash
osv-scanner --experimental-licenses="comma-separated list of allowed licenses" path/to/directory
```

Include your allowed licenses as a comma-separated list. OSV-Scanner recognizes licenses in SPDX format. Please indicate your allowed licenses using [SPDX license](https://spdx.org/licenses/) identifiers.

### License violations example

If you wanted to allow the following licenses:

- [BSD 3-Clause "New" or "Revised" License](https://spdx.org/licenses/BSD-3-Clause.html)
- [Apache License 2.0](https://spdx.org/licenses/Apache-2.0.html)
- [MIT](https://spdx.org/licenses/MIT.html)

Your command would be in this form:

```bash
osv-scanner --experimental-licenses="BSD-3-Clause,Apache-2.0,MIT" path/to/directory
```

## Override License

Sometimes, the license either cannot be retrieved, or does not apply to your specific use. In those cases, you can override the license of a specific package by setting it in the config file.

See the [configuration docs](./configuration.md) for how to do this.
