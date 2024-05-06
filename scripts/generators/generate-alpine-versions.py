#!/usr/bin/env python3

import json
import operator
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# this requires being run on an OS that has a version of "dpkg" which supports the
# "--compare-versions" option; also make sure to consider the version of dpkg being
# used in case there are changes to the comparing logic (last run with 1.19.7).
#
# also note that because of the large amount of versions being used there is
# significant overhead in having to use a subprocess, so this generator caches
# the results of said subprocess calls; a typical no-cache run takes about 5+
# minutes whereas with the cache it only takes seconds.

# An array of version comparisons that are known to be unsupported and so
# should be commented out in the generated fixture.
#
# Generally this is because the native implementation has a suspected bug
# that causes the comparison to return incorrect results, and so supporting
# such comparisons in the detector would in fact be wrong.
UNSUPPORTED_COMPARISONS = []


def is_unsupported_comparison(line):
  return line in UNSUPPORTED_COMPARISONS


def uncomment(line):
  if line.startswith("#"):
    return line[1:]
  if line.startswith("//"):
    return line[2:]
  return line


def download_alpine_db():
  urllib.request.urlretrieve("https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip", "alpine-db.zip")


def extract_packages_with_versions(osvs):
  dict = {}

  for osv in osvs:
    for affected in osv['affected']:
      if not affected['package']['ecosystem'].startswith('Alpine'):
        continue

      package = affected['package']['name']

      if package not in dict:
        dict[package] = []

      for version in affected.get('versions', []):
        dict[package].append(AlpineVersion(version))

  # deduplicate and sort the versions for each package
  for package in dict:
    dict[package] = sorted(list(dict.fromkeys(dict[package])))

  return dict


class AlpineVersionComparer:
  def __init__(self, cache_path):
    self.cache_path = Path(cache_path)
    self.cache = {}

    self._load_cache()

  def _load_cache(self):
    if self.cache_path:
      self.cache_path.touch()
      with open(self.cache_path, "r") as f:
        lines = f.readlines()

        for line in lines:
          line = line.strip()
          key, result = line.split(",")

          if result == "True":
            self.cache[key] = True
            continue
          if result == "False":
            self.cache[key] = False
            continue

          print(f"ignoring invalid cache entry '{line}'")

  def _save_to_cache(self, key, result):
    self.cache[key] = result
    if self.cache_path:
      self.cache_path.touch()
      with open(self.cache_path, "a") as f:
        f.write(f"{key},{result}\n")

  def compare(self, a, op, b):
    key = f"{a} {op} {b}"
    if key in self.cache:
      return self.cache[key]

    cmd = ["docker", "run", "--rm", "alpine:3.10", "apk", "version", "-t", a, b]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if out.returncode != 0:
      raise Exception(f"apk did not like comparing {a} {op} {b}: {out.stderr.decode('utf-8')}")

    r = out.stdout.decode('utf-8').strip() == op
    self._save_to_cache(key, r)
    return r


alpine_comparer = AlpineVersionComparer("/tmp/alpine-versions-generator-cache.csv")


class AlpineVersion:
  def __str__(self):
    return self.version

  def __hash__(self):
    return hash(self.version)

  def __init__(self, version):
    self.version = version

  def __lt__(self, other):
    return alpine_comparer.compare(self.version, '<', other.version)

  def __gt__(self, other):
    return alpine_comparer.compare(self.version, '>', other.version)

  def __eq__(self, other):
    return alpine_comparer.compare(self.version, '=', other.version)


def compare(v1, relate, v2):
  ops = {'<': operator.lt, '=': operator.eq, '>': operator.gt}
  return ops[relate](v1, v2)


def compare_versions(lines, select="all"):
  has_any_failed = False

  for line in lines:
    line = line.strip()

    if line == "" or line.startswith('#') or line.startswith('//'):
      maybe_unsupported = uncomment(line).strip()

      if is_unsupported_comparison(maybe_unsupported):
        print(f"\033[96mS\033[0m: \033[93m{maybe_unsupported}\033[0m")
      continue

    v1, op, v2 = line.strip().split(" ")

    r = compare(AlpineVersion(v1), op, AlpineVersion(v2))

    if not r:
      has_any_failed = r

    if select == "failures" and r:
      continue

    if select == "successes" and not r:
      continue

    color = '\033[92m' if r else '\033[91m'
    rs = "T" if r else "F"
    print(f"{color}{rs}\033[0m: \033[93m{line}\033[0m")
  return has_any_failed


def compare_versions_in_file(filepath, select="all"):
  with open(filepath) as f:
    lines = f.readlines()
    return compare_versions(lines, select)


def generate_version_compares(versions):
  comparisons = []
  for i, version in enumerate(versions):
    if i == 0:
      continue

    comparison = f"{versions[i - 1]} < {version}\n"

    if is_unsupported_comparison(comparison.strip()):
      comparison = "# " + comparison
    comparisons.append(comparison)
  return comparisons


def generate_package_compares(packages):
  comparisons = []
  for package in packages:
    versions = packages[package]
    comparisons.extend(generate_version_compares(versions))

  # return comparisons
  return list(dict.fromkeys(comparisons))


def fetch_packages_versions():
  download_alpine_db()
  osvs = []

  with zipfile.ZipFile('alpine-db.zip') as db:
    for fname in db.namelist():
      with db.open(fname) as osv:
        osvs.append(json.loads(osv.read().decode('utf-8')))

  return extract_packages_with_versions(osvs)


outfile = "internal/semantic/fixtures/alpine-versions-generated.txt"

packs = fetch_packages_versions()
with open(outfile, "w") as f:
  f.writelines(generate_package_compares(packs))
  f.write("\n")

# set this to either "failures" or "successes" to only have those comparison results
# printed; setting it to anything else will have all comparison results printed
show = os.environ.get("VERSION_GENERATOR_PRINT", "failures")

did_any_fail = compare_versions_in_file(outfile, show)

if did_any_fail:
  sys.exit(1)
