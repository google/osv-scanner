Upcoming release:
===

This update adds support for NuGet and Alpine ecosystem, plus various bug fixes by the community.

- [Feature #98](https://github.com/google/osv-scanner/pull/98): Support for NuGet ecosystem.
- [Feature #107](https://github.com/google/osv-scanner/pull/107): Support for Alpine Linux `/lib/apk/db/installed` format.
  - Adds `--check-installed-packages` flag to scan installed packages on Alpine Linux. 
- [Bug #105](https://github.com/google/osv-scanner/issues/105): Fix rare cases of too many open file handles.
- [Bug #131](https://github.com/google/osv-scanner/pull/131): Fix table highlighting overflow.


v1.0.2
===

This is a minor patch release to mitigate human readable output issues on narrow terminals (#85).

- [Bug #85](https://github.com/google/osv-scanner/issues/85): Mitigated by minor fixes.


v1.0.1
===
Various bug fixes and improvements. Many thanks to the amazing contributions and suggestions from the community!

- Feature: ARM64 builds are now also available!
- [Feature #46](https://github.com/google/osv-scanner/pull/46): Gradle lockfile support.
- [Feature #50](https://github.com/google/osv-scanner/pull/46): Add version command.
- [Bug #52](https://github.com/google/osv-scanner/issues/52): Fixes 0 exit code being wrongly emitted when vulnerabilities are present.
