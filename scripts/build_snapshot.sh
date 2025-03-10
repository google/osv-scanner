#!/usr/bin/env bash

set -e

goreleaser build --clean --single-target --snapshot
