#!/usr/bin/env python

import os
import glob


def annotate_file(file, msg):
  if os.getenv("CI") is not None:
    print(f"::error file={file} msg={msg}")


def does_clean_snapshots(pkg_dir):
  try:
    with open(f"{pkg_dir}/testmain_test.go", 'r') as file:
      for _, line in enumerate(file):
        if "	testutility.CleanSnapshots(m)" in line:
          return True
    return False
  except FileNotFoundError:
    return False


def report_lack_of_snapshot_cleaning(directory):
  if os.path.exists(f"{directory}/testmain_test.go"):
    file = f"{directory}/testmain_test.go"

    annotate_file(file, "Make sure that `TestMain` is calling `testutility.CleanSnapshots(m)` after the tests have been run")
    print(f"{file} is not calling `testutility.CleanSnapshots(m)`")
  else:
    file = list(glob.iglob(os.path.join(directory, "*_test.go")))[0]

    annotate_file(file, "Please add a `testmain_test.go` file with a `TestMain` function that calls `testutility.CleanSnapshots(m)` after the tests have been run")
    print(f"{directory} does not have a `testmain_test.go` file with a `TestMain` function that calls `testutility.CleanSnapshots(m)` after the tests have been run")
  pass


uncleaned_snapshots = False
for snapshot_dir in glob.iglob("**/__snapshots__/", recursive=True):
  parent_dir = os.path.dirname(snapshot_dir[:-1])

  if does_clean_snapshots(parent_dir):
    continue

  report_lack_of_snapshot_cleaning(parent_dir)
  uncleaned_snapshots = True

if uncleaned_snapshots:
  print("")
  print("one or more packages are using snapshots but not ensuring they're cleaned up")
  print("make sure these packages have a testmain_test.go file that defines a TestMain function that calls testutility.CleanSnapshots(m)")
  exit(1)
