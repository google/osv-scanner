---
layout: page
title: Experimental Features
permalink: /experimental/
nav_order: 8
---
# Experimental Features

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

### Offline option
The offline database flag `--experimental-offline` causes OSV-Scanner to scan your project against a previously downloaded local database. OSV-Scanner will not download or update the local database, nor will it send any project or dependency information anywhere. When a local database is not present, you will get an error message. No network connection is required when using this flag.  

```bash
osv-scanner --experimental-offline ./path/to/your/dir
```

### Local database option

The local database flag `--experimental-local-db` causes OSV-Scanner to download or update your local database and then scan your project against it. 

```bash
osv-scanner --experimental-local-db ./path/to/your/dir
```

### Manual database download
Instead of using the `--experimental-local-db` flag to download the database, it is possible to manually download the database. 

A downloadable copy of the OSV database is stored in a GCS bucket maintained by OSV:
[`gs://osv-vulnerabilities`](https://osv-vulnerabilities.storage.googleapis.com)

This bucket contains zip files  containing all vulnerabilities for each ecosystem at:
`gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`.

E.g. for PyPI vulnerabilities:

```bash
gsutil cp gs://osv-vulnerabilities/PyPI/all.zip .
```

You can also download over HTTP via https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip .

A list of all current ecosystems is available at 
[`gs://osv-vulnerabilities/ecosystems.txt`](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt).

Set the location of your manually downloaded database by following the instructions [here](./experimental.md#specify-database-location).

### Limitations

1. Commit level scanning is not supported. 
