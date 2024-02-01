#!/usr/bin/env bash

set -e

goreleaser build --rm-dist --single-target --snapshot
