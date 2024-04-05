#!/usr/bin/env bash

set -e

annotate_file() {
  local file="$1"
  local msg="$2"

  if [[ -v "CI" ]]; then
    echo "::error file=$file::$msg"
  fi
}

report_lack_of_snapshot_cleaning() {
  local directory="$1"

  # if this file exists, then the problem will be it's not calling the cleaning function
  if [ -f "$directory/testmain_test.go" ]; then
    file="$directory/testmain_test.go"

    annotate_file "$file" "Make sure that \`TestMain\` is calling \`testutility.CleanSnapshots(m)\` after the tests have been run"
    echo "$file is not calling \`testutility.CleanSnapshots(m)\`"
  else
    file=("$directory"/*_test.go)

    annotate_file "${file[0]}" "Please add a \`testmain_test.go\` file with a \`TestMain\` function that calls \`testutility.CleanSnapshots(m)\` after the tests have been run"
    echo "$directory does not have a \`testmain_test.go\` file with a \`TestMain\` function that calls \`testutility.CleanSnapshots(m)\` after the tests have been run"
  fi
}

uncleaned_snapshots=0

while IFS= read -r snapshot_dir; do
  parent_dir=$(dirname "$snapshot_dir")

  if [ -f "$parent_dir/testmain_test.go" ]; then
    if grep -q "	testutility.CleanSnapshots(m)" "$parent_dir/testmain_test.go"; then
      continue
    fi
  fi

  report_lack_of_snapshot_cleaning "$parent_dir"
  uncleaned_snapshots=1
done < <(find . -type d -name "__snapshots__")

if [ $uncleaned_snapshots -eq 1 ]; then
  echo ""
  echo "one or more packages are using snapshots but not ensuring they're cleaned up"
  echo "make sure these packages have a testmain_test.go file that defines a TestMain function that calls testutility.CleanSnapshots(m)"

  exit 1
fi
