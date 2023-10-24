**Your dependency is vulnerable to [OSV-2023-72](https://osv.dev/list?q=OSV-2023-72)**.

## [OSV-2023-72](https://osv.dev/vulnerability/OSV-2023-72)

<details>
<summary>Details</summary>

> OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=56057
> 
> ```
> Crash type: Heap-buffer-overflow WRITE 4
> Crash state:
> perfetto::trace_processor::TrackEventParser::ParseTrackDescriptor
> perfetto::trace_processor::TrackEventModule::ParseTracePacketData
> perfetto::trace_processor::ProtoTraceParser::ParseTracePacket
> ```
> 

</details>

---

### Affected Packages

| Source | Package Name | Package Version |
| --- | --- | --- |
| lockfile:/usr/local/google/home/rexpan/Documents/Project/engine/deps_flatten.txt | https://fuchsia.googlesource.com/third_party/android.googlesource.com/platform/external/perfetto | b8da07095979310818f0efde2ef3c69ea70d62c5 |

## Remediation

To fix these vulnerabilities, update the vulnerabilities past the listed fixed versions below.

### Fixed Versions

| Vulnerability ID | Package Name | Fixed Version |
| --- | --- | --- |
| OSV-2023-72 | perfetto | 9a7f09383dd39f19e662d428321ca708a2a600a3 |

If you believe these vulnerabilities do not affect your code and wish to ignore them, add them to the ignore list in an
`osv-scanner.toml` file located in the same directory as the lockfile containing the vulnerable dependency.

See the format and more options in our documentation here: https://google.github.io/osv-scanner/configuration/

Add or append these values to the following config files to ignore this vulnerability:

`/usr/local/google/home/rexpan/Documents/Project/engine/osv-scanner.toml`

```
[[IgnoredVulns]]
id = "OSV-2023-72"
reason = "Your reason for ignoring this vulnerability"
```
