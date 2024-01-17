# OSV-Scanner

The present repository contains the source code of the Datadog version of OSV-Scanner.
OSV-Scanner is a project originally owned by Google to extract libraries from package managers' files and match them against the [OSV database](https://osv.dev/).

At Datadog, we use it to extract your dependencies in a CycloneDX formatted SBOM and report it to our backend.

For more details about the full capabilities of the tool, please refer to [the upstream repository](https://www.github.com/google/osv-scanner)

## Getting Started

This section will only explain how to build the project and run the tests. If you intend to only use the tool from pre-built binaries, please refer the [Documentation -> Run](#run) section.

### Build

To build OSV-Scanner you'll need :

- [Python]() 3.10 or later with the [invoke package](https://www.pyinvoke.org/installing.html) installed
- [Go](https://golang.org/doc/install) 1.21 or later. You'll also need to set your `$GOPATH` and have `$GOPATH/bin` in your path.
- [GoReleaser](https://goreleaser.com/) (Optional, only if you want reproducible builds)

You have two ways of producing a binary from the repository, using go build, or using GoReleaser.

#### Build using only go

Run the following command in the project directory:

```bash
./scripts/build.sh
```

It will produce a binary called `osv-scanner` in the project directory

#### Build using goreleaser

Run the following command in the project directory:

```bash
./scripts/build_snapshot.sh
```

See [GoReleaser documentation](https://goreleaser.com/cmd/goreleaser_build/) for build options.

You can reproduce the downloadable builds by checking out the specific tag and running `goreleaser build`, using the same Go version as the one used during the actual release (see goreleaser workflows)

### Run tests

Run the following command in the project directory :

```bash
 ./scripts/run_tests.sh
```

By default, tests that require additional dependencies beyond the go toolchain are skipped. Enable these tests by setting the env variable `TEST_ACCEPTANCE=true`.

You can generate an HTML coverage report by running:

```bash
./scripts/generate_coverage_report.sh
```

### Linting

To lint your code, run the following command :

```bash
./scripts/run_lints.sh
```

### Updating LICENSE-3rdparty.csv

Whenever you need to add or upgrade a dependency, you should update the file called `LICENSE-3rdparty.csv`
(This file represents the different license and copyrights of dependencies used in this project)

To do it, please run the following command :

```bash
inv -e generate-licenses
```

## Documentation

### Run

1. Download the latest version of the scanner from the [release page](https://www.github.com/DataDog/osv-scanner/releases)
2. Export few environment variables :
   1. `REPOSITORY_URL` representing the URL of the repository you scan. Please note that if you run it through a GitHub action, you don't have to export it.
   2. `DD_SITE` representing the region of your Datadog account. It defaults to `us1`
   3. `DD_API_KEY` representing a Datadog API key
3. Run the scanner using the following command :
   ```bash
   ./osv-scanner_<version>_<target>_<architecture> \
      --skip-git \
      --recursive \
      --format=datadog-sbom \
      <path to your repository root directory>
   ```

**Note** : You may want to run the tool only to export the SBOM, in that case you can run the following command :

```bash
./osv-scanner_<version>_<target>_<architecture> \
    --skip-git \
    --recursive \
    --format=datadog-offline-sbom \
    --output=result.json \
    <path to your repository root directory>
```

## Contributing code

This repository is already a fork of [Google's OSV-Scanner](https://www.github.com/google/osv-scanner).

Before contributing, please ensure you want to change a Datadog specific behavior of the scanner.
If not, please consider contributing directly to the upstream repository.

If it is about Datadog's specific behavior, a contributing guide should come up soon. In the meantime, please [open an issue](https://www.github.com/DataDog/osv-scanner/issues) to start the discussion with us

## License

The Datadog version of OSV-Scanner is licensed under the [Apache License, Version 2.0](LICENSE).
