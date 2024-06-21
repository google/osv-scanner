# v1.8.0/v1.8.1:

### Features:

- [Feature #35](https://github.com/google/osv-scanner/issues/35)
  OSV-Scanner now scans transitive dependencies in Maven `pom.xml` files!
  See [our documentation](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/#transitive-dependency-scanning) for more information.
- [Feature #944](https://github.com/google/osv-scanner/pull/944)
  The `osv-scanner.toml` configuration file can now filter specific packages with new `[[PackageOverrides]]` sections:
  ```toml
  [[PackageOverrides]]
  # The package name, version, and ecosystem to match against
  name = "lib"
  # If version is not set or empty, it will match every version
  version = "1.0.0"
  ecosystem = "Go"
  # Ignore this package entirely, including license scanning
  ignore = true
  # Override the license of the package
  # This is not used if ignore = true
  license.override = ["MIT", "0BSD"]
  # effectiveUntil = 2022-11-09 # Optional exception expiry date
  reason = "abc"
  ```

### Minor Updates

- [Feature #1039](https://github.com/google/osv-scanner/pull/1039) The `--experimental-local-db` flag has been removed and replaced with a new flag `--experimental-download-offline-databases` which better reflects what the flag does.  
  To replicate the behavior of the original `--experimental-local-db` flag, replace it with both `--experimental-offline --experimental-download-offline-databases` flags. This will run osv-scanner in offline mode, but download the latest version of the vulnerability databases before scanning.

### Fixes:

- [Bug #1000](https://github.com/google/osv-scanner/pull/1000) Standard dependencies now correctly override `dependencyManagement` dependencies when scanning `pom.xml` files in offline mode.

# v1.7.4:

### Features:

- [Feature #943](https://github.com/google/osv-scanner/pull/943) Support scanning gradle/verification-metadata.xml files.

### Misc:

- [Bug #968](https://github.com/google/osv-scanner/issues/968) Hide unimportant Debian vulnerabilities to reduce noise.

# v1.7.3:

### Features:

- [Feature #934](https://github.com/google/osv-scanner/pull/934) add support for PNPM v9 lockfiles.

### Fixes:

- [Bug #938](https://github.com/google/osv-scanner/issues/938) Ensure the sarif output has a stable order.
- [Bug #922](https://github.com/google/osv-scanner/issues/922) Support filtering on alias IDs in Guided Remediation.

# v1.7.2:

### Fixes:

- [Bug #899](https://github.com/google/osv-scanner/issues/899) Guided Remediation: Parse paths in npmrc auth fields correctly.
- [Bug #908](https://github.com/google/osv-scanner/issues/908) Fix rust call analysis by explicitly disabling stripping of debug info.
- [Bug #914](https://github.com/google/osv-scanner/issues/914) Fix regression for go call analysis introduced in 1.7.0.

# v1.7.1:

(There is no Github release for this version)

### Fixes

- [Bug #856](https://github.com/google/osv-scanner/issues/856)
  Add retry logic to make calls to OSV.dev API more resilient. This combined with changes in OSV.dev's API should result in much less timeout errors.

### API Features

- [Feature #781](https://github.com/google/osv-scanner/pull/781)
  add `MakeVersionRequestsWithContext()`
- [Feature #857](https://github.com/google/osv-scanner/pull/857)
  API and networking related errors now has their own error and exit code (Exit Code 129)

# v1.7.0:

### Features

- [Feature #352](https://github.com/google/osv-scanner/issues/352) Guided Remediation
  Introducing our new experimental guided remediation feature on `osv-scanner fix` subcommand.
  See our [docs](https://google.github.io/osv-scanner/experimental/guided-remediation/) for detailed usage instructions.

- [Feature #805](https://github.com/google/osv-scanner/pull/805)
  Include CVSS MaxSeverity in JSON output.

### Fixes

- [Bug #818](https://github.com/google/osv-scanner/pull/818)
  Align GoVulncheck Go version with go.mod.

- [Bug #797](https://github.com/google/osv-scanner/pull/797)
  Don't traverse gitignored dirs for gitignore files.

### Miscellaneous

- [#831](https://github.com/google/osv-scanner/pull/831)
  Remove version number from the release binary name.

# v1.6.2:

### Features

- [Feature #694](https://github.com/google/osv-scanner/pull/694)
  Add subcommands! OSV-Scanner now has subcommands! The base command has been moved to `scan` (currently the only commands is `scan`).
  By default if you do not pass in a command, `scan` will be used, so CLI remains backwards compatible.

  This is a building block to adding the guided remediation feature. See [issue #352](https://github.com/google/osv-scanner/issues/352)
  for more details!

- [Feature #776](https://github.com/google/osv-scanner/pull/776)
  Add pdm lockfile support.

### API Features

- [Feature #754](https://github.com/google/osv-scanner/pull/754)
  Add dependency groups to flattened vulnerabilities output.

# v1.6.0:

### Features

- [Feature #694](https://github.com/google/osv-scanner/pull/694)
  Add support for NuGet lock files version 2.

- [Feature #655](https://github.com/google/osv-scanner/pull/655)
  Scan and report dependency groups (e.g. "dev dependencies") for vulnerabilities.

- [Feature #702](https://github.com/google/osv-scanner/pull/702)
  Created an option to skip/disable upload to code scanning.

- [Feature #732](https://github.com/google/osv-scanner/pull/732)
  Add option to not fail on vulnerability being found for GitHub Actions.

- [Feature #729](https://github.com/google/osv-scanner/pull/729)
  Verify the spdx licenses passed in to the license allowlist.

### Fixes

- [Bug #736](https://github.com/google/osv-scanner/pull/736)
  Show ecosystem and version even if git is shown if the info exists.

- [Bug #703](https://github.com/google/osv-scanner/pull/703)
  Return an error if both license scanning and local/offline scanning is enabled simultaneously.

- [Bug #718](https://github.com/google/osv-scanner/pull/718)
  Fixed parsing of SBOMs generated by the latest CycloneDX.

- [Bug #704](https://github.com/google/osv-scanner/pull/704)
  Get go stdlib version from go.mod.

### API Features

- [Feature #727](https://github.com/google/osv-scanner/pull/727)
  Changes to `Reporter` methods to add verbosity levels and to deprecate functions.

# v1.5.0:

### Features

- [Feature #501](https://github.com/google/osv-scanner/pull/501)
  Add experimental license scanning support! See https://osv.dev/blog/posts/introducing-license-scanning-with-osv-scanner/ for more information!
- [Feature #642](https://github.com/google/osv-scanner/pull/642)
  Support scanning `renv` files for the R language ecosystem.
- [Feature #513](https://github.com/google/osv-scanner/pull/513)
  Stabilize call analysis for Go! The experimental `--experimental-call-analysis` flag has now been updated to:
  ```
  --call-analysis=<language/all>
  --no-call-analysis=<language/all>
  ```
  with call analysis for Go enabled by default. See https://google.github.io/osv-scanner/usage/#scanning-with-call-analysis for the documentation!
- [Feature #676](https://github.com/google/osv-scanner/pull/676)
  Simplify return codes:
  - Return 0 if there are no findings or errors.
  - Return 1 if there are any findings (license violations or vulnerabilities).
  - Return 128 if no packages are found.
- [Feature #651](https://github.com/google/osv-scanner/pull/651)
  CVSS v4.0 support.
- [Feature #60](https://github.com/google/osv-scanner/pull/60)
  [Pre-commit hook](https://pre-commit.com/) support.

### Fixes

- [Bug #639](https://github.com/google/osv-scanner/issues/639)
  We now filter local packages from scans, and report the filtering of those packages.
- [Bug #645](https://github.com/google/osv-scanner/issues/645)
  Properly handle file/url paths on Windows.
- [Bug #660](https://github.com/google/osv-scanner/issues/660)
  Remove noise from failed lockfile parsing.
- [Bug #649](https://github.com/google/osv-scanner/issues/649)
  No longer include vendored libraries in C/C++ package analysis.
- [Bug #634](https://github.com/google/osv-scanner/issues/634)
  Fix filtering of aliases to also include non OSV aliases

### Miscellaneous

- The minimum go version has been updated to go1.21 from go1.18.

# v1.4.3:

### Features

- [Feature #621](https://github.com/google/osv-scanner/pull/621)
  Add support for scanning vendored C/C++ files.
- [Feature #581](https://github.com/google/osv-scanner/pull/581)
  Scan submodules commit hashes.

### Fixes

- [Bug #626](https://github.com/google/osv-scanner/issues/626)
  Fix gitignore matching for root directory
- [Bug #622](https://github.com/google/osv-scanner/issues/622)
  Go binary not found should not be an error
- [Bug #588](https://github.com/google/osv-scanner/issues/588)
  handle npm/yarn aliased packages
- [Bug #607](https://github.com/google/osv-scanner/pull/607)
  fix: remove some extra newlines in sarif report

# v1.4.2:

### Fixes

- [Bug #574](https://github.com/google/osv-scanner/issues/574)
  Support versions with build metadata in `yarn.lock` files
- [Bug #599](https://github.com/google/osv-scanner/issues/599)
  Add name field to sarif rule output

# v1.4.1:

### Features

- [Feature #534](https://github.com/google/osv-scanner/pull/534)
  New SARIF format that separates out individual vulnerabilities, see https://github.com/google/osv-scanner/issue/216
- [Experimental Feature #57](https://github.com/google/osv-scanner/issues/57) Experimental Github Action!
  Have a look at https://google.github.io/osv-scanner/experimental/ for how to use the new Github Action in your repo.
  Experimental, so might change with only a minor update.

### API Features

- [Feature #557](https://github.com/google/osv-scanner/pull/557) Add new ecosystems, and a slice containing all of them.

# v1.4.0:

### Features

- [Feature #183](https://github.com/google/osv-scanner/pull/183)
  Add (experimental) offline mode! See [our documentation](https://google.github.io/osv-scanner/experimental/#offline-mode) for how to use it.
- [Feature #452](https://github.com/google/osv-scanner/pull/452)
  Add (experimental) rust call analysis, detect whether vulnerable functions are actually called in your Rust project! See [our documentation](https://google.github.io/osv-scanner/experimental/#call-analysis-in-rust) for limitations and how to use this.
- [Feature #484](https://github.com/google/osv-scanner/pull/484) Detect the installed `go` version and checks for vulnerabilities in the standard library.
- [Feature #505](https://github.com/google/osv-scanner/pull/505) OSV-Scanner doesn't support your lockfile format? You can now use your own parser for your format, and create an intermediate `osv-scanner.json` for osv-scanner to scan. See [our documentation](https://google.github.io/osv-scanner/usage/#custom-lockfiles) for instructions.

### API Features

- [Feature #451](https://github.com/google/osv-scanner/pull/451) The lockfile package now support extracting dependencies directly from any io.Reader, removing the requirement of a file path.

### Fixes

- [Bug #457](https://github.com/google/osv-scanner/pull/457)
  Fix PURL mapping for Alpine packages
- [Bug #462](https://github.com/google/osv-scanner/pull/462)
  Use correct plural and singular forms based on count

# v1.3.6:

### Minor Updates

- [Feature #431](https://github.com/google/osv-scanner/pull/431)
  Update GoVulnCheck integration.
- [Feature #439](https://github.com/google/osv-scanner/pull/439)
  Create `models.PURLToPackage()`, and deprecate `osvscanner.PURLToPackage()`.

### Fixes

- [Feature #439](https://github.com/google/osv-scanner/pull/439)
  Fix `PURLToPackage` not returning the full namespace of packages in ecosystems
  that use them (e.g. golang).

# v1.3.5:

### Features

- [Feature #409](https://github.com/google/osv-scanner/pull/409)
  Adds an additional column to the table output which shows the severity if available.

### API Features

- [Feature #424](https://github.com/google/osv-scanner/pull/424)
- [Feature #417](https://github.com/google/osv-scanner/pull/417)
- [Feature #417](https://github.com/google/osv-scanner/pull/417)
  - Update the models package to better reflect the osv schema, including:
    - Add the withdrawn field
    - Improve timestamp serialization
    - Add related field
    - Add additional ecosystem constants
    - Add new reference types
    - Add YAML tags

# v1.3.4:

### Minor Updates

- [Feature #390](https://github.com/google/osv-scanner/pull/390) Add an
  user agent to OSV API requests.

# v1.3.3:

### Fixes

- [Bug #369](https://github.com/google/osv-scanner/issues/369) Fix
  requirements.txt misparsing lines that contain `--hash`.
- [Bug #237](https://github.com/google/osv-scanner/issues/237) Clarify when no
  vulnerabilities are found.
- [Bug #354](https://github.com/google/osv-scanner/issues/354) Fix cycle in
  requirements.txt causing infinite recursion.
- [Bug #367](https://github.com/google/osv-scanner/issues/367) Fix panic when
  parsing empty lockfile.

### API Features

- [Feature #357](https://github.com/google/osv-scanner/pull/357) Update
  `pkg/osv` to allow overriding the http client / transport

# v1.3.2:

### Fixes

- [Bug #341](https://github.com/google/osv-scanner/pull/341) Make the reporter
  public to allow calling DoScan with non nil reporters.
- [Bug #335](https://github.com/google/osv-scanner/issues/335) Improve SBOM
  parsing and relaxing name requirements when explicitly scanning with
  `--sbom`.
- [Bug #333](https://github.com/google/osv-scanner/issues/333) Improve
  scanning speed for regex heavy lockfiles by caching regex compilation.
- [Bug #349](https://github.com/google/osv-scanner/pull/349) Improve SBOM
  documentation and error messages.

# v1.3.1:

### Fixes

- [Bug #319](https://github.com/google/osv-scanner/issues/319) Fix
  segmentation fault when parsing CycloneDX without dependencies.

# v1.3.0:

### Major Features:

- [Feature #198](https://github.com/google/osv-scanner/pull/198) GoVulnCheck
  integration! Try it out when scanning go code by adding the
  `--experimental-call-analysis` flag.
- [Feature #260](https://github.com/google/osv-scanner/pull/198) Support `-r`
  flag in `requirements.txt` files.
- [Feature #300](https://github.com/google/osv-scanner/pull/300) Make
  `IgnoredVulns` also ignore aliases.
- [Feature #304](https://github.com/google/osv-scanner/pull/304) OSV-Scanner
  now runs faster when there's multiple vulnerabilities.

### Fixes

- [Bug #249](https://github.com/google/osv-scanner/issues/249) Support yarn
  locks with quoted properties.
- [Bug #232](https://github.com/google/osv-scanner/issues/232) Parse nested
  CycloneDX components correctly.
- [Bug #257](https://github.com/google/osv-scanner/issues/257) More specific
  cyclone dx parsing.
- [Bug #256](https://github.com/google/osv-scanner/issues/256) Avoid panic
  when parsing `file:` dependencies in `pnpm` lockfiles.
- [Bug #261](https://github.com/google/osv-scanner/issues/261) Deduplicate
  packages that appear multiple times in `Pipenv.lock` files.
- [Bug #267](https://github.com/google/osv-scanner/issues/267) Properly handle
  comparing zero versions in Maven.
- [Bug #279](https://github.com/google/osv-scanner/issues/279) Trim leading
  zeros off when comparing numerical components in Maven versions.
- [Bug #291](https://github.com/google/osv-scanner/issues/291) Check if PURL
  is valid before adding it to queries.
- [Bug #293](https://github.com/google/osv-scanner/issues/293) Avoid infinite
  loops parsing Maven poms with syntax errors
- [Bug #295](https://github.com/google/osv-scanner/issues/295) Set version in
  the source code, this allows version to be displayed in most package
  managers.
- [Bug #297](https://github.com/google/osv-scanner/issues/297) Support Pipenv
  develop packages without versions.

### API Features

- [Feature #310](https://github.com/google/osv-scanner/pull/310) Improve the
  OSV models to allow for 3rd party use of the library.

# v1.2.0:

### Major Features:

- [Feature #168](https://github.com/google/osv-scanner/pull/168) Support for
  scanning debian package status file, usually located in
  `/var/lib/dpkg/status`. Thanks @cmaritan
- [Feature #94](https://github.com/google/osv-scanner/pull/94) Specify what
  parser should be used in `--lockfile`.
- [Feature #158](https://github.com/google/osv-scanner/pull/158) Specify
  output format to use with the `--format` flag.
- [Feature #165](https://github.com/google/osv-scanner/pull/165) Respect
  `.gitignore` files by default when scanning.
- [Feature #156](https://github.com/google/osv-scanner/pull/156) Support
  markdown table output format. Thanks @deftdawg
- [Feature #59](https://github.com/google/osv-scanner/pull/59) Support
  `conan.lock` lockfiles and ecosystem Thanks @SSE4
- Updated documentation! Check it out here:
  https://google.github.io/osv-scanner/

### Minor Updates:

- [Feature #178](https://github.com/google/osv-scanner/pull/178) Support SPDX
  2.3.
- [Feature #221](https://github.com/google/osv-scanner/pull/221) Support
  dependencyManagement section in Maven poms.
- [Feature #167](https://github.com/google/osv-scanner/pull/167) Make
  osvscanner API library public.
- [Feature #141](https://github.com/google/osv-scanner/pull/141) Retry OSV API
  calls to mitigate transient network issues. Thanks @davift
- [Feature #220](https://github.com/google/osv-scanner/pull/220) Vulnerability
  output is ordered deterministically.
- [Feature #179](https://github.com/google/osv-scanner/pull/179) Log number of
  packages scanned from SBOM.
- General dependency updates

### Fixes

- [Bug #161](https://github.com/google/osv-scanner/pull/161) Exit with non
  zero exit code when there is a general error.
- [Bug #185](https://github.com/google/osv-scanner/pull/185) Properly omit
  Source from JSON output.

# v1.1.0:

This update adds support for NuGet ecosystem and various bug fixes by the
community.

- [Feature #98](https://github.com/google/osv-scanner/pull/98): Support for
  NuGet ecosystem.
- [Feature #71](https://github.com/google/osv-scanner/issues/71): Now supports
  Pipfile.lock scanning.
- [Bug #85](https://github.com/google/osv-scanner/issues/85): Even better
  support for narrow terminals by shortening osv.dev URLs.
- [Bug #105](https://github.com/google/osv-scanner/issues/105): Fix rare cases
  of too many open file handles.
- [Bug #131](https://github.com/google/osv-scanner/pull/131): Fix table
  highlighting overflow.
- [Bug #101](https://github.com/google/osv-scanner/issues/101): Now supports
  32 bit systems.

# v1.0.2

This is a minor patch release to mitigate human readable output issues on narrow
terminals (#85).

- [Bug #85](https://github.com/google/osv-scanner/issues/85): Better support
  for narrow terminals.

# v1.0.1

Various bug fixes and improvements. Many thanks to the amazing contributions and
suggestions from the community!

- Feature: ARM64 builds are now also available!
- [Feature #46](https://github.com/google/osv-scanner/pull/46): Gradle
  lockfile support.
- [Feature #50](https://github.com/google/osv-scanner/pull/46): Add version
  command.
- [Bug #52](https://github.com/google/osv-scanner/issues/52): Fixes 0 exit
  code being wrongly emitted when vulnerabilities are present.
