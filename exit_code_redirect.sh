#!/bin/bash

# Execute osv-scanner with the provided arguments
./osv-scanner "$@"

# Store the exit code
exit_code=$?

# Check if the exit code is 127 or 128 and modify it to 0
if [[ $exit_code -eq 127 || $exit_code -eq 128 ]]; then
  exit_code=0
fi

# Exit with the modified exit code
exit $exit_code