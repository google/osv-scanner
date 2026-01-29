#!/usr/bin/env bash

set -ex

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.25.6}"
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1 run ./... "$@"
