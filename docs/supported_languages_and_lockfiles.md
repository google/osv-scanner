---
layout: page
permalink: /supported-languages-and-lockfiles/
nav_order: 2
---

# Supported Artifacts and Manifests

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

Artifact and manifest extraction logic is implemented in [OSV-Scalibr](https://github.com/google/osv-scalibr) as a standalone library. OSV-Scanner tightly integrates with OSV-Scalibr to provide an end to end vulnerability scanner for developers.

## Core Concept

We split the files we can scan into two broad categories, **artifacts** and **manifests**.

We found that when performing different forms of scanning, you are generally interested in different types of files. For example, when scanning your source project, you are much more interested in what your lockfiles and manifests contain, and less interested in what is installed on your development machine, or leftover compiled artifacts. However, if you are scanning a container, then what is installed is the vital piece of information, and lockfiles found on the system no longer matters if the artifacts they point to are not actually downloaded and installed.

## Supported Artifacts

When scanning container images (`osv-scanner scan image ...`), OSV-Scanner automatically extracts and analyzes the following artifacts:

| Source                               | Example files                      |
| ------------------------------------ | ---------------------------------- |
| Alpine APK packages                  | `/lib/apk/db/installed`            |
| Debian/Ubuntu dpkg/apt packages      | `/var/lib/dpkg/status`             |
|                                      |                                    |
| Go Binaries                          | `main-go`                          |
| Rust Binaries (with cargo-auditable) | `main-rust-built-with-auditable`   |
| Java Uber `jars`                     | `my-java-app.jar`                  |
| Node Modules                         | `node-app/node_modules/...`        |
| Python wheels                        | `lib/python3.11/site-packages/...` |

## Supported lockfiles/manifests

When scanning source code (`osv-scanner scan source ...`), OSV-Scanner automatically extracts and analyzes the following lockfiles/manifests:

| Language   | Compatible Lockfile(s)                                                                                                                     |
| :--------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| C/C++      | `conan.lock`<br>[C/C++ commit scanning](#cc-scanning)                                                                                      |
| Dart       | `pubspec.lock`                                                                                                                             |
| Elixir     | `mix.lock`                                                                                                                                 |
| Go         | `go.mod`                                                                                                                                   |
| Haskell    | `cabal.project.freeze`<br> `stack.yaml.lock`                                                                                               |
| Java       | `buildscript-gradle.lockfile`<br>`gradle.lockfile`<br>`gradle/verification-metadata.xml`<br>`pom.xml`[\*](#transitive-dependency-scanning) |
| Javascript | `package-lock.json`<br>`pnpm-lock.yaml`<br>`yarn.lock`                                                                                     |
| .NET       | `deps.json`<br>`packages.config`<br>`packages.lock.json`                                                                                   |
| PHP        | `composer.lock`                                                                                                                            |
| Python     | `Pipfile.lock`<br>`poetry.lock`<br>`requirements.txt`[\*](https://github.com/google/osv-scanner/issues/34)<br>`pdm.lock`<br>`uv.lock`      |
| R          | `renv.lock`                                                                                                                                |
| Ruby       | `Gemfile.lock`                                                                                                                             |
| Rust       | `Cargo.lock`                                                                                                                               |

## C/C++ scanning

With the addition of [vulnerable commit ranges](https://osv.dev/blog/posts/introducing-broad-c-c++-support/) to the OSV.dev database, OSV-Scanner now supports vendored and submoduled C/C++ dependencies

Because the C/C++ ecosystem does not have a centralized package manager, C/C++ dependencies tend to be bundled with the project. Dependencies are either [submoduled](#submoduled-dependencies) or [vendored](#vendored-dependencies). In either case, OSV-Scanner is able to find known vulnerabilities in your project dependencies.

OSV-Scanner's C/C++ support is based on commit-level data. OSV's commit-level data covers the majority of C/C++ vulnerabilities within the OSV database, but users should be aware that there may be vulnerabilities in their dependencies that could be excluded from OSV-Scanner results. Adding more commit-level data to the database is an ongoing project.

### Submoduled dependencies

Submoduled dependencies are included in the project folder retain their Git histories. To scan a C/C++ project with submoduled dependencies:

1. Navigate to the root folder of your project.
2. Ensure that your submodules are up to date using `git submodule update`.
3. Run scanner using `osv-scanner -r .`.

### Vendored dependencies

Vendored dependencies have been directly copied into the project folder, but do not retain their Git histories. OSV-Scanner uses OSV's [determineversion API](https://google.github.io/osv.dev/post-v1-determineversion/) to estimate each dependency's version (and associated Git Commit). Vulnerabilities for the estimated version are returned. This process requires no additional work from the user. Run OSV-Scanner as you normally would.

## Transitive dependency scanning

OSV-Scanner supports transitive dependency scanning for Maven pom.xml. This feature is enabled by default when scanning, but it can be disabled using the `--no-resolve` flag. It is also disabled in the [offline mode](./offline-mode.md).

OSV-Scanner uses [deps.dev’s resolver library](https://pkg.go.dev/deps.dev/util/resolve) to compute the dependency graph of a project. This graph includes all the direct and transitive dependencies. By default, [deps.dev API](https://docs.deps.dev/api/v3/index.html) is queried for package versions and requirements. Support for querying Maven Central and private registries is also available.

After the dependency resolution, the OSV database is queried for the vulnerabilities associated with these dependencies as usual.

{: .note }
Test dependencies are not supported yet in the computed dependency graph for Maven pom.xml.

### Data source

By default, we use the [deps.dev API](https://docs.deps.dev/api/v3/) to find version and dependency information of packages during transitive scanning.

If instead you'd like to fetch data from [Maven Central](https://repo.maven.apache.org/maven2/), you can use the `--data-source=native` flag.

If your project uses mirrored or private registries, in addition to setting `--data-source=native`, you will need to use the `--maven-registry=<full-registry-url>` flag to specify the registry (e.g. `--maven-registry=https://repo.maven.apache.org/maven2/`).

## Custom Lockfiles

If you have a custom lockfile that we do not support or prefer to do your own custom parsing, you can extract the custom lockfile information and create a custom intermediate file containing dependency information so that osv-scanner can still check for vulnerabilities.

Once you extracted your own dependency information, place it in a `osv-scanner.json` file, with the same format as the JSON output of osv-scanner, e.g.:

```jsonc
{
  "results": [
    {
      "packages": [
        {
          "package": {
            "name": "github.com/repo/url",
            "commit": "9a6bd55c9d0722cb101fe85a3b22d89e4ff4fe52"
          }
        },
        {
          "package": {
            "name": "react",
            "version": "1.2.3",
            "ecosystem": "npm"
          }
        }
        // ...
      ]
    }
  ]
}
```

Then pass this to `osv-scanner` with this:

```
osv-scanner --lockfile osv-scanner:/path/to/osv-scanner.json
```
