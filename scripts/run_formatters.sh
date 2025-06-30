#!/usr/bin/env bash

set -ex

# use write unless we're in CI, since Prettier should always be safe to apply
if [ -z "$CI" ]; then
  npx prettier@latest --write .
else
  npx prettier@latest --check .
fi
