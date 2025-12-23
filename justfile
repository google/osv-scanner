# OSV-Scanner Justfile

export PATH := env_var('PATH') + ':' + `go env GOPATH` + '/bin'

# Build scanner
scanner:
    scripts/build.sh

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

# Default values for test configuration
vcr := "ReplayWithNewEpisodes"
snaps := "false"
acc := "false"
short := "true"

# Run tests with configurable modes
# Usage: just vcr=RecordOnly test
#        just acc=true snaps=true test
test:
    #!/usr/bin/env bash
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

# Alias for full tests (not short)
test-full:
    just short=false test

# Alias for acceptance tests
test-acceptance:
    just acc=true test

# Alias for updating snapshots
update-snapshots:
    just snaps=true test

# Alias for recording VCR cassettes
test-record:
    just vcr=RecordOnly test

# Alias for replaying VCR cassettes
test-replay:
    just vcr=ReplayOnly test
