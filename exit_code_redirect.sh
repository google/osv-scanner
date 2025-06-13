#!/bin/bash

# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script works around a limitation of github actions where
# actions cannot receive a variable number of arguments in an array
# This script takes the last argument and splits it out by new line,
# passing it into osv-scanner as separate arguments

# Get the total number of arguments
total_args=$#

# Extract the last argument
last_arg="${!total_args}"

# Remove the last argument from the list
args=${@:1:$((total_args - 1))}

# () interprets spaces as separate entries in an array
# tr replaces newlines with spaces
split_args=($(echo "$last_arg" | tr '\n' ' '))

# Execute osv-scanner with the provided arguments
osv-scanner $args "${split_args[@]}"

# Store the exit code
exit_code=$?

echo "Exit code: ${exit_code}"
# don't error if there are no lockfiles found
if [[ $exit_code -eq 128 ]]; then
  # if the "--allow-no-lockfiles" flag has not been used, print a deprecation warning
  using_new_flag="no"
  for value in "${args[@]}"; do
    if [[ "$value" = "--allow-no-lockfiles" ]] ||
      [[ "$value" ="-allow-no-lockfiles" ]] ||
      [[ "$value" = "-allow-no-lockfiles=true" ]] ||
      [[ "$value" = "--allow-no-lockfiles=true" ]]; then
      using_new_flag="yes"
    fi

    if [[ "$value" =  "-allow-no-lockfiles=false" ]] ||
      [[ "$value" = "--allow-no-lockfiles=false" ]]; then
      exit $exit_code
    fi
  done
  if [[ $using_new_flag = "no" ]]; then
    echo "deprecation warning: please use the --allow-no-lockfiles flag if you don't want this action to error when there are no lockfiles"

    if [[ -n "$CI" ]]; then
      echo "::warning::No lockfiles found. Please use the --allow-no-lockfiles flag to suppress this warning."
    fi
  fi

  exit_code=0
fi

# Exit with the modified exit code
exit $exit_code
