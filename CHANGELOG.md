v1.2.0:
===

### Major Features:

- [Feature #168](https://github.com/google/osv-scanner/pull/168) Support for scanning debian package status file, usually located in `/var/lib/dpkg/status`. Thanks @cmaritan
- [Feature #94](https://github.com/google/osv-scanner/pull/94) Specify what parser should be used in `--lockfile`.
- [Feature #158](https://github.com/google/osv-scanner/pull/158) Specify output format to use with the `--format` flag.
- [Feature #165](https://github.com/google/osv-scanner/pull/165) Respect `.gitignore` files by default when scanning.
- [Feature #156](https://github.com/google/osv-scanner/pull/156) Support markdown table output format. Thanks @deftdawg
- [Feature #59](https://github.com/google/osv-scanner/pull/59) Support `conan.lock` lockfiles and ecosystem Thanks @SSE4
- Updated documentation! Check it out here: https://google.github.io/osv-scanner/

### Minor Updates:
- [Feature #178](https://github.com/google/osv-scanner/pull/178) Support SPDX 2.3.
- [Feature #221](https://github.com/google/osv-scanner/pull/221) Support dependencyManagement section in Maven poms.
- [Feature #167](https://github.com/google/osv-scanner/pull/167) Make osvscanner API library public.
- [Feature #141](https://github.com/google/osv-scanner/pull/141) Retry OSV API calls to mitigate transient network issues. Thanks @davift
- [Feature #220](https://github.com/google/osv-scanner/pull/220) Vulnerability output is ordered deterministically.
- [Feature #179](https://github.com/google/osv-scanner/pull/179) Log number of packages scanned from SBOM.
- General dependency updates

### Fixes
- [Bug #161](https://github.com/google/osv-scanner/pull/161) Exit with non zero exit code when there is a general error.
- [Bug #185](https://github.com/google/osv-scanner/pull/185) Properly omit Source from JSON output.

v1.1.0:
===

This update adds support for NuGet ecosystem and various bug fixes by the community.

- [Feature #98](https://github.com/google/osv-scanner/pull/98): Support for NuGet ecosystem.
- [Feature #71](https://github.com/google/osv-scanner/issues/71): Now supports Pipfile.lock scanning.
- [Bug #85](https://github.com/google/osv-scanner/issues/85): Even better support for narrow terminals by shortening osv.dev URLs.
- [Bug #105](https://github.com/google/osv-scanner/issues/105): Fix rare cases of too many open file handles.
- [Bug #131](https://github.com/google/osv-scanner/pull/131): Fix table highlighting overflow.
- [Bug #101](https://github.com/google/osv-scanner/issues/101): Now supports 32 bit systems.


v1.0.2
===

This is a minor patch release to mitigate human readable output issues on narrow terminals (#85).

- [Bug #85](https://github.com/google/osv-scanner/issues/85): Better support for narrow terminals.


v1.0.1
===
Various bug fixes and improvements. Many thanks to the amazing contributions and suggestions from the community!

- Feature: ARM64 builds are now also available!
- [Feature #46](https://github.com/google/osv-scanner/pull/46): Gradle lockfile support.
- [Feature #50](https://github.com/google/osv-scanner/pull/46): Add version command.
- [Bug #52](https://github.com/google/osv-scanner/issues/52): Fixes 0 exit code being wrongly emitted when vulnerabilities are present.
