#!/usr/bin/env bash

set -ex

docker build -t osv-scanner-docs -f ./docs/docs.Dockerfile ./docs
docker run -p 4000:4000 osv-scanner-docs
