---
layout: page
title: Usage
permalink: /usage/
has_children: true
nav_order: 3
---
# Usage

OSV-Scanner parses lockfiles, SBOMs, and git directories to determine your project's open source dependencies. These dependencies are matched against the OSV database via the [OSV.dev API](https://osv.dev#use-the-api) and known vulnerabilities are returned to you in the output. 

OSV-Scanner supports the following:

- [General project scanning](general.md) including an option to [ignore files](general.md#ignored-files) and to specify [lockfiles](general.md#specify-lockfiles) or [SBOMS](general.md#specify-sbom)
- Docker [image scanning](docker.md#scanning-a-debian-based-docker-image-packages) and running OSV-Scanner in a [Docker container](docker.md#running-in-a-docker-container)
- Matching vulnerabilities through [call graph analysis](call-analysis.md) for [Go and Rust](call-analysis.md#supported-languages)
- [Offline scanning](offline.md)