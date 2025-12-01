#!/usr/bin/env bash

set -e

if [ "$TEST_ACCEPTANCE" = true ]; then
    scripts/build_test_images.sh
fi

if [ "$DOCKER_TEST" = true ]; then
    echo "Building test image..."
    docker build -f scripts/test_env.dockerfile -t osv-scanner-test .

    echo "Running tests in container..."
    # Network host is important to fix DNS resolution issues
    # Docker socket is exposed to access other docker commands for osv-scanner container scanning
    # alpinegomodcache is a named volume to cache go module downloads between runs
    # -it allows Ctrl-C commands to cancel a test
    docker run --rm -it \
        --network host \
        -v "$(pwd):/src" \
        -v "/var/run/docker.sock:/var/run/docker.sock" \
        -v "alpinegomodcache:/go/pkg/mod" \
        -e TEST_ACCEPTANCE="$TEST_ACCEPTANCE" \
        -e UPDATE_SNAPS="$UPDATE_SNAPS" \
        -e TEST_VCR_MODE="$TEST_VCR_MODE" \
        osv-scanner-test \
        sh -c "git config --global --add safe.directory /src && ./scripts/run_tests.sh \"\$@\"" -- "$@"
    exit $?
fi

# If running in CI, test with coverage
if [ -n "$CI" ]; then
    go test ./... -coverpkg=./... -coverprofile coverage.out "$@"
else
    # Use gotestsum which has a nicer test output
    go run gotest.tools/gotestsum@v1.13.0 ./... "$@"
fi
