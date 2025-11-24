#!/usr/bin/env bash

set -e

if [ "$TEST_ACCEPTANCE" = true ]; then
    scripts/build_test_images.sh
fi

if [ "$DOCKER_TEST" = true ]; then
    echo "Building test image..."
    docker build -f scripts/test_env.dockerfile -t osv-scanner-test .

    echo "Running tests in container..."
    docker run --rm \
        -v "$(pwd):/src" \
        -v "/var/run/docker.sock:/var/run/docker.sock" \
        -v "${GOPATH:-$HOME/go}/pkg/mod:/go/pkg/mod" \
        -e TEST_ACCEPTANCE="$TEST_ACCEPTANCE" \
        -e UPDATE_SNAPS="$UPDATE_SNAPS" \
        osv-scanner-test \
        sh -c "git config --global --add safe.directory /src && ./scripts/run_tests.sh \"\$@\"" -- "$@"
    exit $?
fi


go test ./... -coverpkg=./... -coverprofile coverage.out "$@"
