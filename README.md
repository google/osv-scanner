[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv-scanner)

# OSV-Scanner

Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies.

OSV-Scanner provides an officially supported frontend to the [OSV database](https://osv.dev/) that connects a project’s list of dependencies with the vulnerabilities that affect them. Since the OSV.dev database is open source and distributed, it has several benefits in comparison with closed source advisory databases and scanners:

- Each advisory comes from an open and authoritative source (e.g. the [RustSec Advisory Database](https://github.com/rustsec/advisory-db))
- Anyone can suggest improvements to advisories, resulting in a very high quality database
- The OSV format unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer’s list of packages

The above all results in fewer, more actionable vulnerability notifications, which reduces the time needed to resolve them.

## Installing

### Prerequisites
Requires go 1.18+ to be installed

### Installation Process
Run
```bash
$ go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

### SemVer Adherence
All releases on the same Major version will be guaranteed to have backward compatible JSON output and CLI arguments.

## Usage

OSV-Scanner collects a list of dependencies and versions that are used in your project, before matching this list against the OSV database via the [OSV.dev API](https://osv.dev#use-the-api). To build the list of dependencies, you can point OSV-Scanner at your project directory, or manually pass in the path to individual manifest files.

### Scan a directory

Walks through a list of directories to find:
- Lockfiles
- SBOMs
- git directories for the latest commit hash

which is used to build the list of dependencies to be matched against OSV vulnerabilities. 

Can be configured to recursively walk through subdirectories with the `--recursive` / `-r` flag.

Searching for git commit hash is intended to work with projects that use
git submodules or a similar mechanism where dependencies are checked out
as real git repositories.

#### Example

```bash
$ go run ./cmd/osv-scanner -r /path/to/your/dir
```

### Input an SBOM

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents.

[SPDX]: https://spdx.dev/
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

#### Example

```bash
$ go run ./cmd/osv-scanner --sbom=/path/to/your/sbom.json
```

### Input a lockfile

A wide range of lockfiles are supported by utilizing this [lockfile package](https://github.com/google/osv-scanner/tree/main/pkg/lockfile). This is the current list of supported lockfiles:

- `Cargo.lock`        
- `package-lock.json` 
- `yarn.lock`         
- `pnpm-lock.yaml`    
- `composer.lock`     
- `Gemfile.lock`      
- `go.mod`            
- `mix.lock`          
- `poetry.lock`
- `pubspec.lock`
- `pom.xml`[\*](https://github.com/google/osv-scanner/issues/35)        
- `requirements.txt`[\*](https://github.com/google/osv-scanner/issues/34)

#### Example

```bash
$ go run ./cmd/osv-scanner --lockfile=/path/to/your/package-lock.json -L /path/to/another/Cargo.lock
```

### Scanning a Debian based docker image packages

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

#### Example

```bash
$ go run ./cmd/osv-scanner --docker image_name:latest
```

## Configure OSV-Scanner

To configure scanning, place an osv-scanner.toml file in the scanned file's directory. To override this osv-scanner.toml file, pass the `--config=/path/to/config.toml` flag with the path to the configuration you want to apply instead.

Currently, there is only 1 option to configure:
### Ignore vulnerabilities by ID
To ignore a vulnerability, enter the ID under the `IgnoreVulns` key. Optionally, add an expiry date or reason.

#### Example
```
[[IgnoredVulns]]
id = "GO-2022-0968"
# ignoreUntil = 2022-11-09 # Optional exception expiry date
reason = "No ssh servers are connected to or hosted in Go lang"

id = "GO-2022-1059"
# ignoreUntil = 2022-11-09 # Optional exception expiry date
reason = "No external http servers are written in Go lang."
```

## JSON output
By default osv-scanner outputs a human readable table. To have osv-scanner output JSON instead, pass the `--json` flag when calling osv-scanner. 

### Output Format
```json
{
  "results": [
    {
      "packageSource": {
        "path": "/absolute/path/to/go.mod",
        "type": "lockfile"
      },
      "packages": [
        {
          "Package": {
            "name": "github.com/gogo/protobuf",
            "version": "1.3.1",
            "ecosystem": "Go"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-c3h9-896r-86jm",
              "aliases": [
                "CVE-2021-3121"
              ],
              // ... Full OSV
            },
            {
              "id": "GO-2021-0053",
              "aliases": [
                "CVE-2021-3121",
                "GHSA-c3h9-896r-86jm"
              ],
              // ... Full OSV
            }
          ],
          "groups": [
            {
              "ids": [
                "GHSA-c3h9-896r-86jm",
                "GO-2021-0053"
              ]
            }
          ]
        }
      ]
    },
    {
      "packageSource": {
        "path": "/absolute/path/to/Cargo.lock",
        "type": "lockfile"
      },
      "packages": [
        {
          "Package": {
            "name": "regex",
            "version": "1.5.1",
            "ecosystem": "crates.io"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-m5pq-gvj9-9vr8",
              "aliases": [
                "CVE-2022-24713"
              ],
              // ... Full OSV
            },
            {
              "id": "RUSTSEC-2022-0013",
              "aliases": [
                "CVE-2022-24713"
              ],
              // ... Full OSV
            }
          ],
          "groups": [
            {
              "ids": [
                "GHSA-m5pq-gvj9-9vr8",
                "RUSTSEC-2022-0013"
              ]
            }
          ]
        }
      ]
    }
  ]
}
```
