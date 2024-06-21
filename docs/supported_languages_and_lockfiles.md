---
layout: page
title: Supported Languages and Lockfiles
permalink: /supported-languages-and-lockfiles/
nav_order: 2
---

# Supported Languages and Lockfiles

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Supported lockfiles

A wide range of lockfiles are supported by utilizing this [lockfile package](https://github.com/google/osv-scanner/tree/main/pkg/lockfile).

| Language   | Compatible Lockfile(s)                                                                                                                     |
| :--------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| C/C++      | `conan.lock`<br>[C/C++ commit scanning](#cc-scanning)                                                                                      |
| Dart       | `pubspec.lock`                                                                                                                             |
| Elixir     | `mix.lock`                                                                                                                                 |
| Go         | `go.mod`                                                                                                                                   |
| Java       | `buildscript-gradle.lockfile`<br>`gradle.lockfile`<br>`gradle/verification-metadata.xml`<br>`pom.xml`[\*](#transitive-dependency-scanning) |
| Javascript | `package-lock.json`<br>`pnpm-lock.yaml`<br>`yarn.lock`                                                                                     |
| PHP        | `composer.lock`                                                                                                                            |
| Python     | `Pipfile.lock`<br>`poetry.lock`<br>`requirements.txt`[\*](https://github.com/google/osv-scanner/issues/34)<br>`pdm.lock`                   |
| R          | `renv.lock`                                                                                                                                |
| Ruby       | `Gemfile.lock`                                                                                                                             |
| Rust       | `Cargo.lock`                                                                                                                               |

## Alpine Package Keeper and Debian Package Manager

The scanner also supports:

- `installed` files used by the Alpine Package Keeper (apk) that typically live at `/lib/apk/db/installed`
- `status` files used by the Debian Package manager (dpkg) that typically live at `/var/lib/dpkg/status`

however you must [specify](./usage.md/#specify-lockfiles) them explicitly using the `--lockfile` flag:

```bash
osv-scanner --lockfile 'apk-installed:/lib/apk/db/installed'
osv-scanner --lockfile 'dpkg-status:/var/lib/dpkg/status'
```

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

OSV-Scanner supports transitive dependency scanning for Maven pom.xml. This feature is enabled by default when scanning, but it is disabled in the [offline mode](./offline-mode.md).

OSV-Scanner uses [deps.dev’s resolver library](https://pkg.go.dev/deps.dev/util/resolve) to compute the dependency graph of a project. This graph includes all of the direct and transitive dependencies. By default, [deps.dev API](https://docs.deps.dev/api/v3/index.html) is queried for package versions and requirements. The support for private registries is [coming soon](https://github.com/google/osv-scanner/issues/1045).

After the dependency resolution, the OSV database is queried for the vulnerabilities associated with these dependencies as usual.

## Custom Lockfiles

If you have a custom lockfile that we do not support or prefer to do your own custom parsing, you can extract the custom lockfile information and create a custom intermediate file containing dependency information so that osv-scanner can still check for vulnerabilities.

Once you extracted your own dependency information, place it in a `osv-scanner.json` file, with the same format as the JSON output of osv-scanner, e.g.:

```
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
        },
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
