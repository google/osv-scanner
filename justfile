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

# Run tests: snaps=(true|*false), acc=(true|*false), short=(*true|false), vcr=(0[RecordOnly]|1[ReplayOnly]|*2[ReplayWithNewEpisodes])
test *args:
    #!/usr/bin/env bash
    set -e

    # Defaults
    SHORT="true"
    VCR="ReplayWithNewEpisodes"
    
    # Parse args
    for arg in {{args}}; do
        case $arg in
            snaps=true) export UPDATE_SNAPS=true ;;
            snaps=false) unset UPDATE_SNAPS ;;
            acc=true) export TEST_ACCEPTANCE=true ;;
            acc=false) unset TEST_ACCEPTANCE ;;
            short=true) SHORT="true" ;;
            short=false) SHORT="false" ;;
            vcr=*) VCR="${arg#vcr=}" ;;
        esac
    done

    export TEST_VCR_MODE="$VCR"

    ARGS=""
    if [ "$SHORT" = "true" ]; then
        ARGS="$ARGS -short"
    fi

    # execute with constructed args
    scripts/run_tests.sh $ARGS

# Refresh all snaps, matching CI test.
refresh-all rebuild-images="false":
    #!/usr/bin/env bash
    set -e
    if [ "{{rebuild-images}}" = "true" ]; then
        just clean
    fi

    just test acc=true short=false vcr=0
