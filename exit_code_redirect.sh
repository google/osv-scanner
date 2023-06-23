#!/bin/bash

# Get the total number of arguments
total_args=$#

# Extract the last argument
last_arg="${!total_args}"

# Remove the last argument from the list
args=${@:1:$((total_args - 1))}

# Split the last argument by newline
readarray -t split_args <<<"$last_arg"

# Execute osv-scanner with the provided arguments
osv-scanner $args "${split_args[@]}"

# Store the exit code
exit_code=$?

# Check if the exit code is 127 or 128 and modify it to 0
# - 127: General error, not something the user can fix most of the time
# - 128: No lockfiles found
if [[ $exit_code -eq 127 || $exit_code -eq 128 ]]; then
  exit_code=0
fi

# Exit with the modified exit code
exit $exit_code