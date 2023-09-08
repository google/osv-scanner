#!/usr/bin/env bash

set -e
go test ./... -coverpkg=./... -coverprofile coverage.out
