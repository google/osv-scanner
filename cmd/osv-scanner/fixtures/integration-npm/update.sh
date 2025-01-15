#!/bin/bash

VERSIONS=("v6.14.18" "v7.24.2" "v8.19.4" "v10.9.0")

for version in "${VERSIONS[@]}"
do
  cd "$version" || exit
  npx npm@"$version" install
  rm -rf node_modules
  cd - || exit
done
