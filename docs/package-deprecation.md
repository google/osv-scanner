---
layout: page
permalink: /experimental/show-deprecated/
parent: Experimental Features
nav_order: 4
---

# Package Deprecation Reporting

Experimental
{: .label }

OSV-Scanner can identify and report unsupported or removed packages in dependencies.

This feature leverages the [deps.dev API](https://docs.deps.dev/api/).

## Deprecation Status

The `deprecated` field is a boolean value indicating if a package is flagged as unsupported. This includes states such as:

-   **Deprecated**: Marked as deprecated by the author.
-   **Yanked**: Removed from the registry.

## Usage

To enable package deprecation reporting, use the `--show-deprecated` flag.

> Currently, deprecation information is only available in the JSON output. You must specify `--format=json` to view these results.

### Project Source Scanning

```bash
osv-scanner scan source --format=json --show-deprecated -r /path/to/project
```

For more details on source scanning, see [Project Source Scanning](./scan-source.md).

### Container Images Scanning

```bash
# Scan a local or remote image by name
osv-scanner scan image --format=json --show-deprecated my-image:tag

# Scan an exported image archive
osv-scanner scan image --format=json --show-deprecated --archive ./path/to/my-image.tar
```

For more details on image scanning, see [Container Image Scanning](./scan-image.md).

## Output Format

When this feature is enabled, the JSON output includes a `deprecated` field for affected packages. If a package is **not** deprecated, the field is omitted.

<details markdown="block">
<summary>
Example JSON Output
</summary>

```json
{
  "results": [
    {
      "source": {
        "path": "/path/to/lockfile",
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "deprecated-package",
            "version": "1.0.0",
            "ecosystem": "npm",
            "deprecated": true
          }
        },
        {
          "package": {
            "name": "active-package",
            "version": "2.0.0",
            "ecosystem": "npm"
          }
        }
      ]
    }
  ]
}
```

</details>
