#!/usr/bin/env bash

set -e

if [ "$TEST_ACCEPTANCE" = true ]; then
    scripts/build_test_images.sh
fi

go test ./... -coverpkg=./... -coverprofile coverage.out
