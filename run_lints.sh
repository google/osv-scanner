#!/usr/bin/env bash

set -ex

go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.50.1 run ./... --max-same-issues 0
