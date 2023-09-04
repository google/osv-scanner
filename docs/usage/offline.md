---
layout: page
title: Offline Mode
permalink: /usage/offline/
parent: Usage
nav_order: 4
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

