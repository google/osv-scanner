#!/usr/bin/env bash

set -ex

go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.2.1 run ./...
