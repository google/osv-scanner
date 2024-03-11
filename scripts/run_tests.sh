#!/usr/bin/env bash

set -e

scripts/build_test_images.sh

go test ./... -coverpkg=./... -coverprofile coverage.out
