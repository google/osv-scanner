v1.1.0:
===

This update adds support for NuGet ecosystem and various bug fixes by the community.

- [Feature #98](https://github.com/google/osv-scanner/pull/98): Support for NuGet ecosystem.

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
