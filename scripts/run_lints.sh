#!/usr/bin/env bash

set -ex

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.2}"
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(cat .golangci-lint-version) run ./... "$@"
