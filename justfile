# OSV-Scanner Justfile

export PATH := env_var('PATH') + ':' + `go env GOPATH` + '/bin'

# List available commands
default:
    @just --list

# Build scanner
build:
    scripts/build.sh

# Run osv-scanner {args}
scanner *args:
    go run ./cmd/osv-scanner {{args}}

# Run lints
lint:
    scripts/run_lints.sh

# Run formatters
format:
    scripts/run_formatters.sh

# Clean build artifacts
clean:
    rm -f osv-scanner
    rm -r cmd/osv-scanner/scan/image/testdata/test-*.tar

# Run local docs
local-docs:
    scripts/run_local_docs.sh

# Run tests
test snaps="false" acc="false" short="true" vcr="ReplayWithNewEpisodes":
    #!/usr/bin/env bash

    # vcr: ReplayWithNewEpisodes | RecordOnly | ReplayOnly
    # snaps: true | false
    # acc: true | false
    # short: true | false

    export TEST_VCR_MODE="{{vcr}}"
    if [ "{{snaps}}" = "true" ]; then
        export UPDATE_SNAPS=true
    else
        unset UPDATE_SNAPS
    fi
    
    if [ "{{acc}}" = "true" ]; then
        export TEST_ACCEPTANCE=true
    else
        unset TEST_ACCEPTANCE
    fi

    ARGS=""
    if [ "{{short}}" = "true" ]; then
        ARGS="$ARGS -short"
    fi

    # execute with constructed args
    scripts/run_tests.sh $ARGS
