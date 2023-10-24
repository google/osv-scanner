#!/usr/bin/env bash

set -e

./scripts/run_tests.sh

go tool cover -html=coverage.out -o coverage.html
