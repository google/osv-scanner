---
layout: page
permalink: /experimental/manual-plugin-selection/
parent: Experimental Features
nav_order: 5
---

# Manual OSV-Scalibr Plugin Selection

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

By default, OSV-Scanner automatically enables the relevant plugins for each scanning situation
(see [this page](./supported_languages_and_lockfiles.md) for more details).
However, if the default selection is not suitable, or you require additional plugins from OSV-Scalibr (e.g., detectors),
you can manually enable or disable them.

## Enabling and Disabling Plugins

You can control which plugins to run using the following flags:

- `--experimental-plugins`: Enables a comma-separated list of specific plugins that will be used along with the default plugins for the command being run
- `--experimental-disable-plugins`: Disables a comma-separated list of specific plugins.
- `--experimental-no-default-plugins`: Excludes the default plugins for the command being run from being automatically included

For a full list of available plugin names, see OSV-Scalibr's documentation here:
https://github.com/google/osv-scalibr/blob/main/docs/supported_inventory_types.md

### Presets

You can also enable or disable various presets, which group multiple plugins together.

**Example:**

```bash
# This will enable all sbom plugins + cargolock extractor + requirements extractor
osv-scanner scan source --experimental-plugins sbom,rust/cargolock,python/requirements

# This will enable all lockfile plugins, except the cargolock and requirements extractors
osv-scanner scan source --experimental-plugins lockfile --experimental-disable-plugins rust/cargolock,python/requirements
```

**Available Presets:**

| Preset      | Description                     |
| :---------- | :------------------------------ |
| `sbom`      | Default for directory scanning. |
| `lockfile`  | Default for lockfile scanning.  |
| `directory` | Default for directory scanning. |
| `artifact`  | Default for image scanning.     |

### Detectors

OSV-Scalibr provides detectors that can identify potential security issues beyond known vulnerabilities.
We experimentally support these detectors. Currently, detector findings are only available in the JSON output under
`experimental_generic_findings`.

**Available Detector Presets:**

| Preset        | Description                                |
| :------------ | :----------------------------------------- |
| `untested`    | Finds dependencies that are not tested.    |
| `weakcreds`   | Detects weak credentials.                  |
| `govulncheck` | Checks for vulnerabilities in Go binaries. |
| `cis`         | Checks for compliance with CIS benchmarks. |

<details markdown="block">
<summary>
Example detector run
</summary>

```bash
osv-scanner scan image <img> --experimental-plugins=os/apk,weakcredentials/etcshadow --format=json
```

```json
{
  "results": [
    {
      "source": {
        "path": "/lib/apk/db/installed",
        "type": "os"
      },
      "packages": [
        {
          "package": {
            "name": "apk-tools",
            "os_package_name": "apk-tools",
            "version": "2.10.6-r0",
            "ecosystem": "Alpine:v3.10",
            "commit": "ee458ccae264321745e9622c759baf110130eb2f",
            "image_origin_details": {
              "index": 0
            }
          },
          "vulnerabilities": ["CVE-2021-36159"],
          "groups": 1
        }
      ]
    }
  ],
  "experimental_config": {
    "licenses": {
      "summary": false,
      "allowlist": null
    }
  },
  "experimental_generic_findings": [
    {
      "Adv": {
        "ID": {
          "Publisher": "SCALIBR",
          "Reference": "etc-shadow-weakcredentials"
        },
        "Title": "Ensure all users have strong passwords configured",
        "Description": "The /etc/shadow file contains user account password hashes. These passwords must be strong and not easily guessable.",
        "Recommendation": "Run the following command to reset password for the reported users:/n# change password for USER: sudo passwd USER",
        "Sev": 5
      },
      "Target": {
        "Extra": "/etc/shadow: The following users have weak passwords:/nuser-bcrypt/n"
      },
      "Plugins": ["weakcredentials/etcshadow"],
      "ExploitabilitySignals": null
    }
  ],
  "image_metadata": {
    "os": "Alpine Linux v3.10",
    "layer_metadata": [
      {
        "diff_id": "sha256:...",
        "command": "/bin/sh -c #(nop) ADD file:c5377eaa926bf412dd8d4a08b0a1f2399cfd708743533b0aa03b53d14cb4bb4e in / ",
        "is_empty": false,
        "base_image_index": 1
      },
      {
        "diff_id": "",
        "command": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
        "is_empty": true,
        "base_image_index": 1
      },
      {
        "diff_id": "sha256:...",
        "command": "RUN /bin/sh -c echo 'user-bcrypt:$2b$05$IYDlXvHmeORyyiUwu8KKuek2LE8VrxIYZ2skPvRDDNngpXJHRq7sG' /u003e/u003e /etc/shadow # buildkit",
        "is_empty": false,
        "base_image_index": 0
      },
      {
        "diff_id": "sha256:...",
        "command": "RUN /bin/sh -c echo 'user-descrypt:chERDiI95PGCQ' /u003e/u003e /etc/shadow # buildkit",
        "is_empty": false,
        "base_image_index": 0
      }
    ],
    "base_images": [
      {},
      {
        "name": "alpine",
        "tags": null
      }
    ]
  }
}
```

</details>
