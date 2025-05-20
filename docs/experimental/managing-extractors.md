---
layout: page
parent: Experimental Features
---

# Managing Extractors

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

Under the hood, `osv-scanner` uses "extractors" to extract package information that it then runs checks against such as
seeing if there are any known vulnerabilities or license violations, depending on what flags you call the scanner with.

By default, the scanner handles determining what extractors to use, but developers can explicitly enable or disable
particular extractors with the `--experimental-extractors` and `--experimental-disable-extractors` flags; you can also
pass in a ...

## Key doc points

- we have a set of presets (`artifacts`, `directories`, `lockfiles`, `sboms`)
  - the subcommand...
    - `image` uses the `artifacts` present by default
    - `scan` uses the `directories`, `lockfiles`, and `sboms` presents by default
  - the present...
    - `artifacts` is used when scanning containers
      - (w/ the `image` subcommand)
      - `directories` is used when scanning directories (+ `lockfiles` and `sboms`)
      - `lockfiles` is used when scanning specific files
      - `sboms` is used when scanning sboms via the `--sbom` flag
        - in the long-run we want to deprecate this in favor of `-L`
- extractors follow [this interface](https://github.com/google/osv-scalibr/blob/main/extractor/extractor.go#L24-L31)
- extractors specify their names, so you need to look that up from the extractor package itself
- at least one extractor must be enabled
- specifying an extractor means only that extractor will be used (so you need to specify "all" of them)
  - currently the extractor has some private extractors, meaning it's not possible to "append one custom extractor"
    - `github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored`
    - `github.com/google/osv-scanner/v2/internal/scalibrextract/language/java/pomxmlenhanceable`
    - `github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules`
    - `github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo`
- you can mix-and-match with presets
  - i.e. `--experimental-extractors=lockfiles --experimental-disable-extractors=php/composerlock`
